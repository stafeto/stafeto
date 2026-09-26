// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The test init (spec 15.2). It runs in place of init on the normal
//! build of the kernel, the one that ships, and tests the system calls
//! from EL0, in its own process, in children with no code and in children
//! it loads from the boot image, the child program (tests/child). The
//! contract of the calls is checked here and only here: the order of
//! their checks, their rights, and that on an error x0 alone changes
//! (spec 11), the caller's own ceiling among them, which a child under a
//! lower ceiling checks; the kernel tests keep what a program cannot see
//! or reach, such as a caller's full table or the kernel's own state after
//! a call. It prints `TEST <name> ok` or `TEST <name> FAIL <why>`
//! for each test, then `TESTS DONE total=<n> failed=<m>`, and exits with
//! the number of failures, which turns the machine off; xtask reads the
//! lines.
//!
//! Its first line gives the counter ticks of a counted loop, which xtask
//! checks in the runs under -icount. The first test runs with the
//! priority the kernel gave init; the others with init at TEST_PRIORITY.
//! A thread above it runs at once; threads below it run when init lowers
//! itself to 1 (`let_run`), and init runs again once they all have ended
//! or wait: the order of priorities joins threads. Init hears of the end
//! of a child through the child's exit channel (`wait_exit`, `Kid::end`,
//! spec 7.9).
//! Notifications that init takes in its own thread have priority 1
//! (QUIET), and init asks once more afterwards: their boost never lifts
//! init above its threads (spec 6.6).

#![no_std]
#![no_main]

use abi::{
    Access, CHANNEL_RIGHTS, CLIENT_GONE, Call, Error, INIT_BOOT_IMAGE, MemoryInfo, Policy,
    ProcessHandles, ProcessMemory, ProcessState, Rights, Source,
};
use bootimg::{Part, Program};
use child::{Checked, Role};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use rt::handle::{Channel, Memory, Process, Thread, Timer};
use rt::sys::{self, Received, Regs, Reply, Token};
use rt::{Handle, Stack, init, loader, println, time};

rt::entry!(main);

type Outcome = Result<(), &'static str>;
/// A test's name and body.
type Test = (&'static str, fn() -> Outcome);

const TESTS: [Test; 159] = [
    ("init_starts_fifo_at_63", init_starts_fifo_at_63),
    ("init_prints_from_el0", init_prints_from_el0),
    (
        "init_handles_have_their_fixed_values",
        init_handles_have_their_fixed_values,
    ),
    (
        "boot_image_is_a_read_only_memory_object",
        boot_image_is_a_read_only_memory_object,
    ),
    ("init_has_its_message_buffer", init_has_its_message_buffer),
    (
        "debug_write_checks_its_arguments",
        debug_write_checks_its_arguments,
    ),
    ("unknown_system_calls_fail", unknown_system_calls_fail),
    ("priority_ceilings_hold", priority_ceilings_hold),
    (
        "thread_set_priority_checks_its_arguments",
        thread_set_priority_checks_its_arguments,
    ),
    (
        "thread_create_checks_its_arguments",
        thread_create_checks_its_arguments,
    ),
    (
        "thread_start_and_process_kill_check_their_handles",
        thread_start_and_process_kill_check_their_handles,
    ),
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
    (
        "process_create_checks_its_arguments",
        process_create_checks_its_arguments,
    ),
    ("quota_is_enforced", quota_is_enforced),
    ("process_info_kinds", process_info_kinds),
    ("kernel_stats_need_kstats", kernel_stats_need_kstats),
    (
        "object_info_checks_its_arguments",
        object_info_checks_its_arguments,
    ),
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
        "handle_duplicate_checks_its_arguments",
        handle_duplicate_checks_its_arguments,
    ),
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
        "sources_give_their_slots_back",
        sources_give_their_slots_back,
    ),
    (
        "exit_notice_comes_after_the_quota",
        exit_notice_comes_after_the_quota,
    ),
    (
        "exit_notice_carries_the_label",
        exit_notice_carries_the_label,
    ),
    ("exit_channel_needs_notify", exit_channel_needs_notify),
    (
        "exit_priority_under_the_ceiling",
        exit_priority_under_the_ceiling,
    ),
    (
        "start_channel_moves_into_the_child",
        start_channel_moves_into_the_child,
    ),
    ("start_channel_needs_transfer", start_channel_needs_transfer),
    (
        "start_handle_must_be_a_channel",
        start_handle_must_be_a_channel,
    ),
    (
        "client_gone_when_the_child_dies",
        client_gone_when_the_child_dies,
    ),
    (
        "clock_now_follows_the_counter",
        clock_now_follows_the_counter,
    ),
    ("timer_needs_receive", timer_needs_receive),
    (
        "timer_set_and_cancel_check_their_handles",
        timer_set_and_cancel_check_their_handles,
    ),
    ("timer_bounds_a_wait", timer_bounds_a_wait),
    (
        "notification_before_the_timer_comes_first",
        notification_before_the_timer_comes_first,
    ),
    (
        "timer_in_the_past_fires_at_once",
        timer_in_the_past_fires_at_once,
    ),
    ("timer_set_moves_the_deadline", timer_set_moves_the_deadline),
    ("cancel_keeps_posted_bits", cancel_keeps_posted_bits),
    ("timer_never_fires_early", timer_never_fires_early),
    ("timer_limit_is_64", timer_limit_is_64),
    (
        "timer_fires_at_its_slot_priority",
        timer_fires_at_its_slot_priority,
    ),
    (
        "mem_create_checks_its_arguments",
        mem_create_checks_its_arguments,
    ),
    (
        "mem_create_takes_the_whole_object_at_once",
        mem_create_takes_the_whole_object_at_once,
    ),
    (
        "closed_object_gives_its_frames_back",
        closed_object_gives_its_frames_back,
    ),
    (
        "memory_info_reports_size_pages_and_mappings",
        memory_info_reports_size_pages_and_mappings,
    ),
    ("mem_map_checks_its_arguments", mem_map_checks_its_arguments),
    ("map_access_is_r_rw_or_rx", map_access_is_r_rw_or_rx),
    (
        "map_needs_the_rights_of_its_access",
        map_needs_the_rights_of_its_access,
    ),
    (
        "two_mappings_show_the_same_pages",
        two_mappings_show_the_same_pages,
    ),
    (
        "mem_unmap_takes_whole_mappings",
        mem_unmap_takes_whole_mappings,
    ),
    (
        "mem_protect_takes_whole_mappings_within_their_rights",
        mem_protect_takes_whole_mappings_within_their_rights,
    ),
    ("mapping_limit_is_64", mapping_limit_is_64),
    (
        "buffer_page_cannot_be_mapped_over",
        buffer_page_cannot_be_mapped_over,
    ),
    (
        "buffer_page_cannot_be_unmapped",
        buffer_page_cannot_be_unmapped,
    ),
    (
        "buffer_page_cannot_be_protected",
        buffer_page_cannot_be_protected,
    ),
    ("busy_mapping_is_bad_state", busy_mapping_is_bad_state),
    (
        "thread_buffer_cannot_land_in_a_mapping",
        thread_buffer_cannot_land_in_a_mapping,
    ),
    ("long_calls_let_a_timer_in", long_calls_let_a_timer_in),
    (
        "mapped_object_outlives_its_last_handle",
        mapped_object_outlives_its_last_handle,
    ),
    (
        "protect_to_exec_runs_new_code",
        protect_to_exec_runs_new_code,
    ),
    ("init_segments_are_taken", init_segments_are_taken),
    (
        "child_with_code_runs_and_exits",
        child_with_code_runs_and_exits,
    ),
    (
        "child_loads_in_its_least_quota",
        child_loads_in_its_least_quota,
    ),
    (
        "request_through_the_start_channel",
        request_through_the_start_channel,
    ),
    (
        "child_bad_address_ends_it_with_the_reason",
        child_bad_address_ends_it_with_the_reason,
    ),
    ("child_cannot_write_its_code", child_cannot_write_its_code),
    ("child_cannot_run_its_data", child_cannot_run_its_data),
    ("child_stack_has_a_guard_page", child_stack_has_a_guard_page),
    (
        "child_read_only_mapping_refuses_a_write",
        child_read_only_mapping_refuses_a_write,
    ),
    (
        "child_executable_mapping_refuses_a_write",
        child_executable_mapping_refuses_a_write,
    ),
    (
        "child_access_after_unmap_faults",
        child_access_after_unmap_faults,
    ),
    ("child_panic_exits_with_101", child_panic_exits_with_101),
    (
        "grandchildren_die_with_their_parent",
        grandchildren_die_with_their_parent,
    ),
    (
        "child_table_churn_stays_under_its_quota",
        child_table_churn_stays_under_its_quota,
    ),
    (
        "el0_fault_ends_only_the_process",
        el0_fault_ends_only_the_process,
    ),
    ("wfi_at_el0_is_a_fault", wfi_at_el0_is_a_fault),
    (
        "last_thread_exit_ends_the_process",
        last_thread_exit_ends_the_process,
    ),
    (
        "process_exit_ends_the_process_with_its_code",
        process_exit_ends_the_process_with_its_code,
    ),
    ("process_kills_itself", process_kills_itself),
    (
        "exited_thread_gives_its_buffer_back",
        exited_thread_gives_its_buffer_back,
    ),
    (
        "orphan_exit_frees_the_process",
        orphan_exit_frees_the_process,
    ),
    (
        "orphan_fault_frees_the_process",
        orphan_fault_frees_the_process,
    ),
    (
        "child_notifies_through_its_start_channel",
        child_notifies_through_its_start_channel,
    ),
    (
        "reply_from_another_process_is_bad_state",
        reply_from_another_process_is_bad_state,
    ),
    (
        "boost_is_capped_by_the_server_ceiling",
        boost_is_capped_by_the_server_ceiling,
    ),
    (
        "client_of_a_dead_server_gets_peer_closed",
        client_of_a_dead_server_gets_peer_closed,
    ),
    (
        "reply_to_a_dead_client_is_peer_closed",
        reply_to_a_dead_client_is_peer_closed,
    ),
    (
        "a_call_cycle_ends_with_the_kill",
        a_call_cycle_ends_with_the_kill,
    ),
    ("send_checks_its_arguments", send_checks_its_arguments),
    (
        "request_carries_registers_and_label",
        request_carries_registers_and_label,
    ),
    (
        "bytes_past_the_length_come_as_zero",
        bytes_past_the_length_come_as_zero,
    ),
    ("reply_carries_registers_back", reply_carries_registers_back),
    ("second_reply_is_bad_state", second_reply_is_bad_state),
    (
        "send_without_waiting_is_would_block",
        send_without_waiting_is_would_block,
    ),
    (
        "send_without_waiting_to_a_waiting_server_gets_the_reply",
        send_without_waiting_to_a_waiting_server_gets_the_reply,
    ),
    ("requests_come_by_priority", requests_come_by_priority),
    (
        "requests_and_notifications_share_one_order",
        requests_and_notifications_share_one_order,
    ),
    (
        "server_below_its_client_runs_at_the_client",
        server_below_its_client_runs_at_the_client,
    ),
    ("boost_ends_with_its_reply", boost_ends_with_its_reply),
    ("other_reply_keeps_the_boost", other_reply_keeps_the_boost),
    ("receive_ends_a_request_boost", receive_ends_a_request_boost),
    (
        "high_client_waits_for_one_started_request",
        high_client_waits_for_one_started_request,
    ),
    (
        "send_to_a_closed_channel_is_peer_closed",
        send_to_a_closed_channel_is_peer_closed,
    ),
    (
        "queued_client_gets_peer_closed_on_close",
        queued_client_gets_peer_closed_on_close,
    ),
    (
        "accepted_request_outlives_the_close",
        accepted_request_outlives_the_close,
    ),
    ("close_runs_at_the_top_waiter", close_runs_at_the_top_waiter),
    (
        "client_gone_comes_after_queued_requests",
        client_gone_comes_after_queued_requests,
    ),
    (
        "set_priority_moves_a_waiting_sender",
        set_priority_moves_a_waiting_sender,
    ),
    (
        "notification_boost_outlives_an_older_reply",
        notification_boost_outlives_an_older_reply,
    ),
    (
        "exited_threads_hold_no_numbers",
        exited_threads_hold_no_numbers,
    ),
    ("buffer_address_is_in_tpidrro", buffer_address_is_in_tpidrro),
    ("long_request_arrives_whole", long_request_arrives_whole),
    ("long_reply_arrives_whole", long_reply_arrives_whole),
    (
        "short_message_leaves_the_buffers_alone",
        short_message_leaves_the_buffers_alone,
    ),
    (
        "kernel_leaves_bytes_0_to_63_of_the_buffer",
        kernel_leaves_bytes_0_to_63_of_the_buffer,
    ),
    ("bytes_past_the_length_stay", bytes_past_the_length_stay),
    // Before the tests that fill init's table: a table that grew to its
    // limit takes no chunk again.
    (
        "receiver_quota_fails_the_sender",
        receiver_quota_fails_the_sender,
    ),
    (
        "failed_create_keeps_the_start_handle",
        failed_create_keeps_the_start_handle,
    ),
    ("handles_move_with_a_request", handles_move_with_a_request),
    ("handles_move_with_a_reply", handles_move_with_a_reply),
    ("rights_stay_narrowed", rights_stay_narrowed),
    (
        "label_travels_with_its_handle",
        label_travels_with_its_handle,
    ),
    (
        "receive_right_moves_without_closing_the_channel",
        receive_right_moves_without_closing_the_channel,
    ),
    (
        "a_failed_check_takes_no_handle",
        a_failed_check_takes_no_handle,
    ),
    (
        "peer_closed_takes_the_handles",
        peer_closed_takes_the_handles,
    ),
    (
        "full_waiting_receiver_fails_the_sender",
        full_waiting_receiver_fails_the_sender,
    ),
    (
        "queued_request_that_does_not_fit_fails_its_sender",
        queued_request_that_does_not_fit_fails_its_sender,
    ),
    (
        "reply_that_does_not_fit_fails_both",
        reply_that_does_not_fit_fails_both,
    ),
    (
        "closed_handle_stays_bad_after_many_transfers",
        closed_handle_stays_bad_after_many_transfers,
    ),
    (
        "send_handle_cannot_travel_in_its_own_send",
        send_handle_cannot_travel_in_its_own_send,
    ),
    ("same_handle_twice_is_invalid", same_handle_twice_is_invalid),
    (
        "memory_object_carries_a_request",
        memory_object_carries_a_request,
    ),
    (
        "memory_object_comes_back_in_a_reply",
        memory_object_comes_back_in_a_reply,
    ),
    (
        "narrowed_memory_handle_maps_read_only",
        narrowed_memory_handle_maps_read_only,
    ),
    ("shared_pages_show_both_sides", shared_pages_show_both_sides),
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
const SLOTS: usize = 4;
/// The label of the copy of a test's exit channel that names its
/// children (process_create x3).
const CHILD: u64 = 0xC41D;
/// The label of the copy of a channel a timer is made through.
const TIMED: u64 = 0x71AE;
/// The bits a thread of init notifies with before a timer's deadline.
const NOTIFIED: u64 = 0b1001;

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
/// A line debug_write prints with all 64 bytes of x2-x9.
const LINE: &[u8; 64] = b"test init: debug_write prints all 64 bytes of x2 to x9 in order\n";

fn main(_: u64) -> u64 {
    rt::console::set(&init::RESOURCE);
    println!("counter ticks of 10000 turns: {}", loop_ticks());
    if let Err(why) = prepare() {
        println!("test init: no children with code: {why}");
    }
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

/// Init's first handles name what spec 13.3 gives it, with the rights
/// abi gives them: copies with abi::INIT_RESOURCE_RIGHTS and
/// abi::OWNER_RIGHTS are made.
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
    )?;
    let copies = [
        sys::handle_duplicate(&init::RESOURCE, abi::INIT_RESOURCE_RIGHTS).map(close),
        sys::handle_duplicate(&init::PROCESS, abi::OWNER_RIGHTS).map(close),
        sys::handle_duplicate(&init::THREAD, abi::OWNER_RIGHTS).map(close),
    ];
    check(
        copies.iter().all(|c| matches!(c, Ok(Ok(())))),
        "init's first handles do not carry every right abi gives them",
    )
}

/// The boot image is a read-only memory object (spec 13.1, 13.3):
/// INIT_BOOT_IMAGE reports its size in whole pages and no page of its own;
/// mapped R at WINDOW, besides the mapping at IMAGE the run keeps, it
/// shows `STAFBOOT` at its start, and RW and RX fail with ACCESS_DENIED
/// alone; a copy with TRANSFER is made, and its close gives no frame back.
fn boot_image_is_a_read_only_memory_object() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let image: Handle<Memory> = Handle::from_raw(INIT_BOOT_IMAGE);
    let info = sys::memory_info(&image).map_err(|_| "MEMORY of INIT_BOOT_IMAGE failed")?;
    check(
        info.size > 0 && info.size.is_multiple_of(PAGE as u64) && info.pages == 0,
        "the boot image is not whole pages of frames it does not own",
    )?;
    let denied = [Access::ReadWrite, Access::ReadExec]
        .into_iter()
        .all(|access| {
            let args = [
                init::PROCESS.raw().0,
                INIT_BOOT_IMAGE.0,
                0,
                info.size,
                WINDOW as u64,
                access.raw(),
            ];
            x0_alone::<N>(&args, Error::AccessDenied.code())
        });
    map(&image, 0, info.size, WINDOW, Access::Read)?;
    let mapped = sys::memory_info(&image).map(|i| i.mappings);
    // SAFETY: the window maps the boot image, read-only.
    let signature = unsafe { (WINDOW as *const [u8; 8]).read_volatile() };
    unmap(WINDOW, info.size)?;
    check(denied, "the boot image mapped RW or RX")?;
    check(
        mapped == Ok(2) && signature == *b"STAFBOOT",
        "the mapping of the boot image does not show its signature",
    )?;
    let travel = copy(&image, Rights::MAP_READ | Rights::TRANSFER)?;
    let before = counts()?;
    close(travel)?;
    check(
        counts()? == before,
        "the close of a copy of the boot image gave frames back",
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

/// debug_write(x0 resource with DEBUG, x1 length, x2-x9 bytes) checks the
/// length first, then the handle, its type and its rights (spec 11), and
/// changes x0 alone on an error: a length past 64 fails with INVALID_ARGS,
/// through a closed handle too; a closed handle and handle 0 fail with
/// BAD_HANDLE, a process with WRONG_TYPE, a copy of the resource without
/// DEBUG with ACCESS_DENIED. A good call writes the bytes of its length and
/// returns their count in x1 alone: all 64 bytes of x2-x9 in order, and
/// only those of a shorter length; xtask finds both lines whole.
fn debug_write_checks_its_arguments() -> Outcome {
    let gone = closed_handle()?;
    let stats = copy(&init::RESOURCE, Rights::KSTATS)?;
    let result = debug_write_cases(gone, stats.raw().0);
    close(stats)?;
    result
}

fn debug_write_cases(gone: u64, no_debug: u64) -> Outcome {
    const N: u16 = Call::DebugWrite.number();
    let resource = init::RESOURCE.raw().0;
    let past = abi::INLINE_MAX as u64 + 1;
    let lengths = [
        (resource, past),
        (resource, u64::MAX),
        (resource, 1 << 32),
        (gone, past),
    ]
    .into_iter()
    .all(|(h, len)| x0_alone::<N>(&[h, len], Error::InvalidArgs.code()));
    let handles = [
        (gone, Error::BadHandle),
        (0, Error::BadHandle),
        (init::PROCESS.raw().0, Error::WrongType),
        (no_debug, Error::AccessDenied),
    ]
    .into_iter()
    .all(|(h, error)| x0_alone::<N>(&[h, 1], error.code()));
    check(
        lengths,
        "a length past 64 did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "a closed handle, handle 0, a process or a copy without DEBUG did not fail alone",
    )?;
    check(
        written(LINE) && written(STOPS),
        "debug_write did not write the bytes of its length and return their count alone",
    )?;
    check(
        sys::debug_write(&init::RESOURCE, b"\n") == Ok(1),
        "debug_write did not write a newline",
    )
}

/// debug_write of `line` with `#` past it in x2-x9 returns the length of
/// `line` in x1 and changes nothing past it.
fn written(line: &[u8]) -> bool {
    let mut bytes = [b'#'; abi::INLINE_MAX];
    bytes[..line.len()].copy_from_slice(line);
    let mut x = marked();
    x[..2].copy_from_slice(&[init::RESOURCE.raw().0, line.len() as u64]);
    x[2..].copy_from_slice(&abi::inline_words(&bytes));
    // SAFETY: debug_write only reads its registers.
    let after = unsafe { sys::raw::<{ Call::DebugWrite.number() }>(x) };
    after[..2] == [0, line.len() as u64] && after[2..] == x[2..]
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

/// The end of the lower half, where the addresses of programs lie
/// (spec 7.2).
const LOWER_END: u64 = 1 << 48;

/// The value of a copy of the system resource that init closed: BAD_HANDLE
/// from then on (spec 5.1).
fn closed_handle() -> Result<u64, &'static str> {
    let h = copy(&init::RESOURCE, Rights::NONE)?;
    let value = h.raw().0;
    close(h)?;
    Ok(value)
}

/// Call `N` with `args` in x0 and up and marks in the rest of x0-x9: true
/// when x0 comes back as `x0`, 0 or the code of an error, and no other
/// register changed (spec 11).
fn x0_alone<const N: u16>(args: &[u64], x0: u64) -> bool {
    let mut x = marked();
    x[..args.len()].copy_from_slice(args);
    // SAFETY: the tests pass arguments the call refuses, or make a call
    // that returns nothing; none of them runs code of init or uses its
    // memory.
    let after = unsafe { sys::raw::<N>(x) };
    after[0] == x0 && after[1..] == x[1..]
}

/// thread_set_priority(x0 thread with MANAGE, x1 priority, x2 policy)
/// checks its values first, then the handle, then the ceilings, then the
/// thread's state (spec 8, 11), and changes x0 alone on an error: a
/// priority outside 1-63 or with bits past its byte and a policy other
/// than round robin and FIFO fail with INVALID_ARGS, through a closed
/// handle too; a closed handle fails with BAD_HANDLE, the system resource
/// with WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED. A priority
/// above the ceiling of the thread's process, 20 here, fails with
/// ACCESS_DENIED, and still does once the process ended, before
/// BAD_STATE. So does one above the ceiling of the caller's own process:
/// a child under ceiling 30 gives a thread of a process under 63 30, and
/// 31 fails (`caller_ceiling`).
fn thread_set_priority_checks_its_arguments() -> Outcome {
    let gone = closed_handle()?;
    let c = child(20)?;
    let t = child_thread(&c, LEVEL);
    let result = match &t {
        Ok(t) => set_priority_cases(&c, t, gone),
        Err(_) => Err("thread_create in the child failed"),
    };
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    result.and_then(|()| caller_ceiling(Checked::ThreadSetPriority))
}

fn set_priority_cases(c: &Handle<Process>, t: &Handle<Thread>, gone: u64) -> Outcome {
    const N: u16 = Call::ThreadSetPriority.number();
    let (rr, fifo) = (Policy::RoundRobin as u64, Policy::Fifo as u64);
    let weak = copy(t, Rights::DUPLICATE)?;
    let h = t.raw().0;
    let values = [(0, rr), (64, rr), (0x100 | 10, rr), (10, 2), (10, 1 << 32)]
        .into_iter()
        .all(|(priority, policy)| {
            [h, gone]
                .into_iter()
                .all(|h| x0_alone::<N>(&[h, priority, policy], Error::InvalidArgs.code()))
        });
    let handles = [
        (gone, Error::BadHandle),
        (init::RESOURCE.raw().0, Error::WrongType),
        (weak.raw().0, Error::AccessDenied),
    ]
    .into_iter()
    .all(|(h, error)| x0_alone::<N>(&[h, 10, rr], error.code()));
    let ceiling =
        x0_alone::<N>(&[h, 21, rr], Error::AccessDenied.code()) && x0_alone::<N>(&[h, 20, rr], 0);
    let killed = sys::process_kill(c);
    let ended = x0_alone::<N>(&[h, 21, fifo], Error::AccessDenied.code())
        && x0_alone::<N>(&[h, 20, fifo], Error::BadState.code());
    close(weak)?;
    check(
        values,
        "a bad priority or policy did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "a closed handle, the resource or a copy without MANAGE did not fail alone",
    )?;
    check(
        ceiling,
        "the ceiling of the thread's process did not hold, or its level was refused",
    )?;
    check(
        killed.is_ok() && ended,
        "a thread whose process ended did not fail with ACCESS_DENIED above the ceiling and BAD_STATE under it",
    )
}

/// thread_create(x0 process with MANAGE, x1 entry, x2 stack, x3 argument,
/// x4 priority, x5 policy, x6 buffer) checks its values first, then the
/// handle, then the ceilings, then whether the buffer's page is free in
/// the process (spec 8, 11), and changes x0 alone on an error: an entry
/// past the lower half or off a whole instruction, a stack past it or off
/// 16 bytes, a priority outside 1-63, an unknown policy and a buffer at
/// page 0, off a whole page or past the lower half fail with INVALID_ARGS,
/// through a closed handle too; a closed handle fails with BAD_HANDLE, a
/// thread with WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED. The
/// page of another thread's buffer fails with INVALID_ARGS, after the
/// ceiling of the process, 20 here. A priority above the caller's own
/// ceiling fails with ACCESS_DENIED too: a child under ceiling 30 makes no
/// thread at 31 in a process under 63 (`caller_ceiling`).
fn thread_create_checks_its_arguments() -> Outcome {
    let gone = closed_handle()?;
    let c = child(20)?;
    let t = child_thread(&c, LEVEL);
    let result = match &t {
        Ok(t) => thread_create_cases(&c, t, gone),
        Err(_) => Err("thread_create in the child failed"),
    };
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    result.and_then(|()| caller_ceiling(Checked::ThreadCreate))
}

fn thread_create_cases(c: &Handle<Process>, t: &Handle<Thread>, gone: u64) -> Outcome {
    const N: u16 = Call::ThreadCreate.number();
    let weak = copy(c, Rights::DUPLICATE)?;
    let fifo = Policy::Fifo as u64;
    // The page after the child's thread's buffer is free.
    let (entry, stack, free) = (CHILD_ENTRY, 0x80_1000, CHILD_BUFFER + PAGE as u64);
    let args =
        |h, entry, stack, priority, policy, buffer| [h, entry, stack, 7, priority, policy, buffer];
    let values = [c.raw().0, gone].into_iter().all(|h| {
        [
            args(h, LOWER_END, stack, 10, fifo, free),
            args(h, entry + 2, stack, 10, fifo, free),
            args(h, entry, stack - 8, 10, fifo, free),
            args(h, entry, LOWER_END + 16, 10, fifo, free),
            args(h, entry, stack, 0, fifo, free),
            args(h, entry, stack, 64, fifo, free),
            args(h, entry, stack, 10, 2, free),
            args(h, entry, stack, 10, fifo, free + 8),
            args(h, entry, stack, 10, fifo, LOWER_END),
            args(h, entry, stack, 10, fifo, 0),
        ]
        .iter()
        .all(|a| x0_alone::<N>(a, Error::InvalidArgs.code()))
    });
    let handles = [
        (gone, Error::BadHandle),
        (t.raw().0, Error::WrongType),
        (weak.raw().0, Error::AccessDenied),
    ]
    .into_iter()
    .all(|(h, error)| x0_alone::<N>(&args(h, entry, stack, 10, fifo, free), error.code()));
    let taken = x0_alone::<N>(
        &args(c.raw().0, entry, stack, 10, fifo, CHILD_BUFFER),
        Error::InvalidArgs.code(),
    ) && x0_alone::<N>(
        &args(c.raw().0, entry, stack, 21, fifo, CHILD_BUFFER),
        Error::AccessDenied.code(),
    );
    close(weak)?;
    check(
        values,
        "a bad entry, stack, priority, policy or buffer did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "a closed handle, a thread or a copy without MANAGE did not fail alone",
    )?;
    check(
        taken,
        "a buffer on a taken page did not fail with INVALID_ARGS after the ceiling",
    )
}

/// thread_start(x0 thread with MANAGE) and process_kill(x0 process with
/// MANAGE) check their handle (spec 11) and change x0 alone on an error:
/// handle 0 fails with BAD_HANDLE, a handle of the other kind with
/// WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED. A stopped thread
/// of a process that ended does not start: BAD_STATE.
fn thread_start_and_process_kill_check_their_handles() -> Outcome {
    let c = child(LOW)?;
    let t = child_thread(&c, LOW);
    let result = match &t {
        Ok(t) => start_and_kill_cases(&c, t),
        Err(_) => Err("thread_create in the child failed"),
    };
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    result
}

fn start_and_kill_cases(c: &Handle<Process>, t: &Handle<Thread>) -> Outcome {
    const START: u16 = Call::ThreadStart.number();
    const KILL: u16 = Call::ProcessKill.number();
    let (weak_c, weak_t) = (copy(c, Rights::DUPLICATE)?, copy(t, Rights::DUPLICATE)?);
    let refused = [
        x0_alone::<START>(&[0], Error::BadHandle.code()),
        x0_alone::<START>(&[c.raw().0], Error::WrongType.code()),
        x0_alone::<START>(&[weak_t.raw().0], Error::AccessDenied.code()),
        x0_alone::<KILL>(&[0], Error::BadHandle.code()),
        x0_alone::<KILL>(&[t.raw().0], Error::WrongType.code()),
        x0_alone::<KILL>(&[weak_c.raw().0], Error::AccessDenied.code()),
    ];
    let killed = sys::process_kill(c);
    let late = x0_alone::<START>(&[t.raw().0], Error::BadState.code());
    close(weak_c)?;
    close(weak_t)?;
    check(
        refused.iter().all(|&ok| ok),
        "handle 0, a handle of the other kind or a copy without MANAGE did not fail alone",
    )?;
    check(
        killed.is_ok() && late,
        "a stopped thread of a process that ended did not fail with BAD_STATE alone",
    )
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
/// child; init hears of the end on the child's exit channel (spec 7.9),
/// object_info tells it why, and the kernel prints the fault, which xtask
/// reads whole.
fn child_fault_reason_reaches_the_parent() -> Outcome {
    let (exits, name) = exit_channel()?;
    let c = heard_child(&name, QUIET, HIGH)?;
    let t = child_thread(&c, HIGH).map_err(|_| "thread_create in the child failed")?;
    let started = sys::thread_start(&t);
    let heard = wait_exit(&exits, CHILD);
    let state = sys::process_state(&c);
    close(t)?;
    close(c)?;
    close(exits)?;
    close(name)?;
    check(started.is_ok(), "thread_start failed")?;
    heard?;
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
/// the child (spec 7.7): the kill takes it off the queue, so when init
/// lets the threads below it run, the child, whose first act would mark
/// its start in the page of marks, marks nothing, and the reason is
/// «killed». A second kill of the dead child succeeds.
fn kill_takes_a_ready_thread_off_the_queue() -> Outcome {
    reset_kid_marks();
    let kid = Kid::load(LEAF_QUOTA, 16, LOW)?;
    let started = kid.start();
    let killed = sys::process_kill(&kid.process);
    // A thread left on the queue would run now, above init at 1.
    let_run()?;
    let state = sys::process_state(&kid.process);
    let again = sys::process_kill(&kid.process);
    let ended = kid.end();
    kid.close()?;
    check(
        started.is_ok() && killed.is_ok(),
        "thread_start or process_kill failed",
    )?;
    check(
        kid_mark(child::STARTED) == 0,
        "the child's thread ran after the kill",
    )?;
    check(
        state == Ok(ProcessState::Killed) && ended == Ok(ProcessState::Killed),
        "the child did not end as killed",
    )?;
    check(again.is_ok(), "a second kill of the dead child failed")
}

/// process_create(x0 quota, x1 table limit, x2 ceiling, x3 exit channel,
/// x4 its priority, x5 start channel) checks its values before its
/// handles (spec 7.5, 11) and changes x0 alone on an error: a quota of 0
/// or off whole pages, a limit outside 1-16384 or with bits past its word
/// and a ceiling outside 1-63 or with bits past its byte fail with
/// INVALID_ARGS, with closed handles in x3 and x5 too; so do a priority in
/// x4 without an exit channel and an exit channel without one, whatever
/// x3 holds. What x3 and x5 name is exit_channel_needs_notify and
/// start_handle_must_be_a_channel. A ceiling above the caller's own fails
/// with ACCESS_DENIED alone after the handles in x3 and x5 and before the
/// quota: 31 in a child under ceiling 30 (`caller_ceiling`).
fn process_create_checks_its_arguments() -> Outcome {
    const N: u16 = Call::ProcessCreate.number();
    let gone = closed_handle()?;
    let page = PAGE as u64;
    let values = [
        [0, 16, 20],
        [page - 1, 16, 20],
        [page + 8, 16, 20],
        [page, 0, 20],
        [page, 16_385, 20],
        [page, 1 << 32 | 16, 20],
        [page, 16, 0],
        [page, 16, 64],
        [page, 16, 0x100 | 20],
    ]
    .into_iter()
    .all(|[quota, limit, ceiling]| {
        [[0, 0, 0], [gone, 5, gone]]
            .into_iter()
            .all(|[x3, x4, x5]| {
                x0_alone::<N>(
                    &[quota, limit, ceiling, x3, x4, x5],
                    Error::InvalidArgs.code(),
                )
            })
    });
    let pairs = [[0, 5], [gone, 0]]
        .into_iter()
        .all(|[x3, x4]| x0_alone::<N>(&[page, 16, 20, x3, x4, 0], Error::InvalidArgs.code()));
    check(
        values,
        "a bad quota, limit or ceiling did not fail with INVALID_ARGS alone before the handles",
    )?;
    check(
        pairs,
        "x4 without x3 or x3 without x4 did not fail with INVALID_ARGS alone",
    )?;
    caller_ceiling(Checked::ProcessCreate)
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
/// though it writes; init's resource gets the counts in x1-x8 and changes
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
        after[0] == 0 && after[9..] == x[9..],
        "KERNEL_STATS failed or changed registers past x8",
    )?;
    let stats = abi::KernelStats::from_words(after[1..9].try_into().expect("x1-x8"));
    check(
        stats.cleanup_queue == 0 && stats.free_frames > 0 && stats.pool_pages > 0,
        "the queue is not empty, or no frame or pool page is counted",
    )
}

/// object_info(x0 handle, x1 kind, x2 0) checks the kind and x2 first,
/// then the handle, its type and its rights (spec 11, 16), and changes x0
/// alone on an error: kind 0, a kind past MEMORY or with bits past its
/// word and a nonzero x2 fail with INVALID_ARGS, for handle 0 too;
/// handle 0 with a good kind fails with BAD_HANDLE. The kinds of a process
/// take a process handle with any rights, and the system resource or a
/// thread is WRONG_TYPE; KERNEL_STATS takes the system resource with
/// KSTATS, and a process is WRONG_TYPE, a copy without KSTATS
/// ACCESS_DENIED. A good call writes nothing past its words:
/// PROCESS_STATE, «alive» here, x1-x4, PROCESS_MEMORY and PROCESS_HANDLES
/// x1-x3.
fn object_info_checks_its_arguments() -> Outcome {
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let debug = copy(&init::RESOURCE, Rights::DEBUG)?;
    let result = object_info_cases(own.raw().0, debug.raw().0);
    close(own)?;
    close(debug)?;
    result
}

fn object_info_cases(own: u64, debug: u64) -> Outcome {
    const N: u16 = Call::ObjectInfo.number();
    let (state, memory, table, stats) = (
        abi::INFO_PROCESS_STATE,
        abi::INFO_PROCESS_MEMORY,
        abi::INFO_PROCESS_HANDLES,
        abi::INFO_KERNEL_STATS,
    );
    let (resource, thread) = (init::RESOURCE.raw().0, init::THREAD.raw().0);
    let kinds = [
        [own, 0, 0],
        [own, abi::INFO_MEMORY + 1, 0],
        [own, state | 1 << 32, 0],
        [own, state, 8],
        [0, 0, 0],
    ]
    .into_iter()
    .chain(
        [memory, table, stats, abi::INFO_MEMORY]
            .into_iter()
            .flat_map(|kind| [[own, kind, 1], [0, kind, 1]]),
    )
    .all(|args| x0_alone::<N>(&args, Error::InvalidArgs.code()));
    let handles = [
        (0, state, Error::BadHandle),
        (0, memory, Error::BadHandle),
        (0, table, Error::BadHandle),
        (0, stats, Error::BadHandle),
        (resource, state, Error::WrongType),
        (thread, state, Error::WrongType),
        (resource, memory, Error::WrongType),
        (resource, table, Error::WrongType),
        (own, stats, Error::WrongType),
        (debug, stats, Error::AccessDenied),
    ]
    .into_iter()
    .all(|(h, kind, error)| x0_alone::<N>(&[h, kind, 0], error.code()));
    let written = [(state, 5), (memory, 4), (table, 4)].map(|(kind, past)| {
        let mut x = marked();
        x[..3].copy_from_slice(&[own, kind, 0]);
        // SAFETY: object_info only reads its registers.
        let after = unsafe { sys::raw::<N>(x) };
        (after[0] == 0 && after[past..] == x[past..]).then_some(after)
    });
    check(
        kinds,
        "a bad kind or x2 did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "handle 0, a handle of another kind or one without KSTATS did not fail alone",
    )?;
    check(
        written.iter().all(Option::is_some),
        "a good object_info failed or wrote past its words",
    )?;
    check(
        written[0].is_some_and(|after| after[1..5] == ProcessState::Alive.to_words()),
        "PROCESS_STATE of init's process through a copy with no rights is not «alive»",
    )
}

/// Init at TEST_PRIORITY kills a child with a thread: the cleanup runs at
/// init's level before the call returns (spec 7.7), so right afterwards
/// the queue is empty, the exit notification is there (spec 7.9), and the
/// child gave back all but the pages of its pools of threads and blocks,
/// which go with its shell (spec 7.8): the shell of its thread, which
/// init's handle keeps, lies in one of them.
fn process_kill_returns_after_the_teardown() -> Outcome {
    let (exits, name) = exit_channel()?;
    let c = heard_child(&name, QUIET, LOW)?;
    let t = child_thread(&c, LOW);
    let killed = sys::process_kill(&c);
    let stats = sys::kernel_stats(&init::RESOURCE);
    let memory = sys::process_memory(&c);
    let heard = take_one(&exits);
    let made = t.is_ok() && killed.is_ok();
    close(c)?;
    if let Ok(t) = t {
        close(t)?;
    }
    close(exits)?;
    close(name)?;
    check(made, "thread_create or process_kill failed")?;
    check(
        heard == Ok(exit_notice(CHILD)),
        "the exit notification was not there when process_kill returned",
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

/// CYCLES rounds of a child with a ready thread, killed and closed, and
/// of its exit notification leave init's used memory, the free frames and
/// the pages of kernel pools as they were, exactly (spec 7.5, 7.8): each
/// child gives back every frame it took and the pages of its pools with
/// its shell, which goes once init took the notification, and the kill
/// takes the kernel's reference to the thread along. One round runs
/// first: the page of init's pool of shells that it takes stays init's.
fn create_kill_cycles_leak_nothing() -> Outcome {
    let (exits, name) = exit_channel()?;
    let result = cycles(&exits, &name);
    close(exits)?;
    close(name)?;
    result
}

fn cycles(exits: &Handle<Channel>, name: &Handle<Channel>) -> Outcome {
    cycle(exits, name)?;
    let before = counts()?;
    for _ in 0..CYCLES {
        cycle(exits, name)?;
    }
    let after = counts()?;
    check(
        after.0 == before.0,
        "init's used memory grew over the rounds",
    )?;
    check(after.1 == before.1, "frames were lost over the rounds")?;
    check(after.2 == before.2, "the pools took pages over the rounds")
}

/// A child with a started thread that init kills and forgets, and whose
/// exit notification init takes. The thread is ready below init and never
/// runs: the kill takes it off the queue.
fn cycle(exits: &Handle<Channel>, name: &Handle<Channel>) -> Outcome {
    let c = heard_child(name, QUIET, LOW)?;
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
    )?;
    wait_exit(exits, CHILD)
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
/// A priority above the caller's ceiling fails with ACCESS_DENIED alone:
/// 31 in a child under ceiling 30 (`caller_ceiling`).
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
    )?;
    caller_ceiling(Checked::CreateChannel)
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
/// ORed, the count 3, and receive writes 0 as the label and the token in
/// x10 and x11, whatever they held (spec 11). The slot is empty
/// afterwards.
fn notifications_merge_bits_and_count() -> Outcome {
    let c = channel(QUIET)?;
    let posted = [0b001, 0b100, 0b100 | 1 << 40]
        .into_iter()
        .try_for_each(|bits| sys::notify(&c, bits));
    let got = receive_x0_to_x11(c.raw(), 0x5A, 0x5B);
    let rest = sys::try_receive(&c);
    close(c)?;
    check(posted.is_ok(), "notify failed")?;
    let merged = abi::Notification {
        source: Source::Unlabeled,
        label: 0,
        bits: 0b101 | 1 << 40,
        count: 3,
    };
    check(
        got[0] == 0 && got[1..] == merged.to_words(),
        "the bits did not merge, the count is not 3, or x10 and x11 are not 0",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "a second receive found something",
    )
}

/// receive with NO_WAIT through `h`, with `x10` and `x11` in x10 and x11:
/// x0-x11 as the kernel left them (spec 11).
fn receive_x0_to_x11(h: abi::Handle, x10: u64, x11: u64) -> [u64; 12] {
    let mut x = [0; 12];
    x[..2].copy_from_slice(&[h.0, abi::NO_WAIT]);
    x[10..].copy_from_slice(&[x10, x11]);
    // SAFETY: receive uses no memory of the program and changes x0-x11
    // only.
    unsafe {
        core::arch::asm!(
            "svc #{n}",
            n = const Call::Receive.number(),
            inout("x0") x[0],
            inout("x1") x[1],
            inout("x2") x[2],
            inout("x3") x[3],
            inout("x4") x[4],
            inout("x5") x[5],
            inout("x6") x[6],
            inout("x7") x[7],
            inout("x8") x[8],
            inout("x9") x[9],
            inout("x10") x[10],
            inout("x11") x[11],
            options(nostack),
        )
    };
    x
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

/// handle_duplicate(x0 handle, x1 rights, x2 label, x3 priority) checks
/// its values first, then the handle, whether a label goes on it, then its
/// rights (spec 5.3, 11), and changes x0 alone on an error: a priority
/// without a label, a label without a priority and a priority outside
/// 1-63 or with bits past its byte fail with INVALID_ARGS through a closed
/// handle too; a closed handle and handle 0 fail with BAD_HANDLE; a label
/// on what is no channel fails with WRONG_TYPE, a copy without DUPLICATE
/// of init's process too; a label on a channel copy without DUPLICATE
/// fails with ACCESS_DENIED. Rights no right has and rights the original
/// lacks are duplicate_narrows_rights. The priority of a label above the
/// caller's own ceiling fails with ACCESS_DENIED alone after the handle and
/// before whether a label goes on it: 31 in a child under ceiling 30
/// (`caller_ceiling`).
fn handle_duplicate_checks_its_arguments() -> Outcome {
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let result = duplicate_cases(gone, notify_only.raw().0, own.raw().0);
    close(own)?;
    close(notify_only)?;
    close(c)?;
    result.and_then(|()| caller_ceiling(Checked::Label))
}

fn duplicate_cases(gone: u64, notify_only: u64, own: u64) -> Outcome {
    const N: u16 = Call::HandleDuplicate.number();
    let notify = u64::from(Rights::NOTIFY.0);
    let values = [[0, 0, 5], [0, 7, 0], [0, 7, 64], [0, 7, 0x100 | 5]]
        .into_iter()
        .all(|[rights, label, priority]| {
            x0_alone::<N>(&[gone, rights, label, priority], Error::InvalidArgs.code())
        });
    let handles = x0_alone::<N>(&[gone, 0, 0, 0], Error::BadHandle.code())
        && x0_alone::<N>(&[0, 0, 7, 5], Error::BadHandle.code());
    let kinds = [init::RESOURCE.raw().0, own]
        .into_iter()
        .all(|h| x0_alone::<N>(&[h, 0, 7, 5], Error::WrongType.code()));
    let right = x0_alone::<N>(&[notify_only, notify, 7, 5], Error::AccessDenied.code());
    check(
        values,
        "a bad label or priority did not fail with INVALID_ARGS alone before the handle",
    )?;
    check(
        handles,
        "a closed handle or handle 0 did not fail with BAD_HANDLE alone",
    )?;
    check(
        kinds,
        "a label on what is no channel did not fail with WRONG_TYPE alone before the rights",
    )?;
    check(
        right,
        "a label on a copy without DUPLICATE did not fail with ACCESS_DENIED alone",
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
/// it runs before notify returns. A priority above the caller's own
/// ceiling is handle_duplicate_checks_its_arguments.
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
/// next label fails with LIMIT_REACHED and changes x0 alone, and so does a
/// child with the channel as its exit channel, even with a quota init has
/// not: the slot comes before the quota (spec 11). Once receive took the
/// first CLIENT_GONE, that session went, and a new label fits. Every
/// session leaves with CLIENT_GONE, in the order they left.
fn slot_limit_is_1024() -> Outcome {
    let c = channel(QUIET)?;
    let last = u64::from(abi::MAX_SLOTS) - 1;
    for label in 1..=last {
        close(session(&c, Rights::NONE, label, QUIET)?)?;
    }
    let x = duplicate_regs(c.raw(), Rights::NONE, last + 1, QUIET.into());
    let after = raw_duplicate(x);
    let own = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let mut y = create_regs(c.raw(), QUIET.into(), abi::Handle::INVALID);
    y[0] = (own.quota - own.returned - own.used + 1).next_multiple_of(PAGE as u64);
    let exit = raw_create(y);
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
        failed(exit, y, Error::LimitReached),
        "an exit channel with no slot left did not fail with LIMIT_REACHED before the quota",
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

/// Spec 15.2 (notifications): a source of notifications gives its slot of
/// the channel back as it goes (spec 6.5). On one channel, a thousand
/// times, a session leaves with CLIENT_GONE, a timer goes, and a child
/// whose exit channel it is ends; then 1023 sessions still fit beside the
/// slot of label 0, and the next one fails with LIMIT_REACHED.
fn sources_give_their_slots_back() -> Outcome {
    const ROUNDS: u64 = 1000;
    let c = channel(QUIET)?;
    let churned = (1..=ROUNDS).try_for_each(|label| {
        close(session(&c, Rights::NONE, label, QUIET)?)?;
        let gone = sys::try_receive(&c);
        close(timer(&c)?)?;
        let child = sys::process_create_with(LEAST_QUOTA, 16, LOW, Some((&c, QUIET)), None);
        close(child.map_err(|_| "process_create with an exit channel failed")?)?;
        let ended = sys::try_receive(&c);
        check(
            gone == Ok(labelled(label, CLIENT_GONE, 1)) && ended == Ok(exit_notice(0)),
            "a session or a child did not leave with its notification",
        )
    });
    let last = u64::from(abi::MAX_SLOTS) - 1;
    let filled = churned.and_then(|()| {
        (1..=last).try_for_each(|label| close(session(&c, Rights::NONE, label, QUIET)?))
    });
    let past = sys::handle_label(&c, Rights::NONE, last + 1, QUIET);
    let refused = past.as_ref().err() == Some(&Error::LimitReached);
    if let Ok(h) = past {
        close(h)?;
    }
    while sys::try_receive(&c).is_ok() {}
    close(c)?;
    filled?;
    check(
        refused,
        "a session past 1023 and the slot of label 0 was made",
    )
}

/// A test's exit channel, at QUIET, and a copy of it with NOTIFY and the
/// label CHILD that names the test's children as their x3. Closing the
/// channel first lets the copy's session go without CLIENT_GONE.
fn exit_channel() -> Result<(Handle<Channel>, Handle<Channel>), &'static str> {
    let exits = channel(QUIET)?;
    let name = session(&exits, Rights::NOTIFY, CHILD, QUIET)?;
    Ok((exits, name))
}

/// A child with no code like `child`, whose end the channel of `name`
/// hears of at `priority` (process_create x3, x4; spec 7.9).
fn heard_child(
    name: &Handle<Channel>,
    priority: u8,
    ceiling: u8,
) -> Result<Handle<Process>, &'static str> {
    sys::process_create_with(CHILD_QUOTA, 16, ceiling, Some((name, priority)), None)
        .map_err(|_| "process_create with an exit channel failed")
}

/// The exit notification of a child whose exit channel carried `label`:
/// bit 0, once (spec 7.9).
fn exit_notice(label: u64) -> Received {
    Received::Notification {
        source: Source::Exit,
        label,
        bits: 1,
        count: 1,
    }
}

/// Waits in receive on `exits` for the exit notification of the child
/// whose exit channel carried `label` (spec 7.9); then a receive without
/// waiting ends its boost and finds nothing more.
fn wait_exit(exits: &Handle<Channel>, label: u64) -> Outcome {
    let got = sys::receive(exits);
    let rest = sys::try_receive(exits);
    check(
        got == Ok(exit_notice(label)),
        "the exit notification did not come with the child's label",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the exit notification",
    )
}

/// x0-x9 for process_create of a child with CHILD_QUOTA, 16 handles and
/// ceiling LOW, and `x3`, `x4` and `x5`, the rest marked.
fn create_regs(x3: abi::Handle, x4: u64, x5: abi::Handle) -> Regs {
    let mut x = marked();
    x[..6].copy_from_slice(&[CHILD_QUOTA, 16, LOW.into(), x3.0, x4, x5.0]);
    x
}

/// process_create with raw registers.
fn raw_create(x: Regs) -> Regs {
    // SAFETY: process_create only reads its registers.
    unsafe { sys::raw::<{ Call::ProcessCreate.number() }>(x) }
}

/// The call failed with `error` and changed x0 alone.
fn failed(after: Regs, x: Regs, error: Error) -> bool {
    after[0] == error.code() && after[1..] == x[1..]
}

/// Spec 7.9: the parent hears of a child's end once the child gave back
/// the free part of its quota. A thread of init above init waits on the
/// exit channel; init kills the child, whose teardown runs at init's
/// level, and the notification wakes the thread in the middle of it:
/// PROCESS_MEMORY of the child shows then that the child returned its
/// quota but what it still uses.
fn exit_notice_comes_after_the_quota() -> Outcome {
    reset_marks();
    let (exits, name) = exit_channel()?;
    let c = heard_child(&name, QUIET, LOW)?;
    MARKS[1].store(c.raw().0, Relaxed);
    let w = spawn(0, watch_exit, exits.raw().0, HIGH, Policy::Fifo)?;
    let killed = sys::process_kill(&c);
    let (heard, returned, free) = (mark(0), mark(2), mark(3));
    close(w)?;
    close(c)?;
    close(exits)?;
    close(name)?;
    check(killed.is_ok(), "process_kill failed")?;
    check(
        heard == 1,
        "the waiting thread did not get the exit notification",
    )?;
    check(
        returned > 0 && returned == free,
        "the exit notification came before the child's quota went back",
    )
}

/// A thread of init that waits in receive on the channel `h` for the exit
/// notification of the child whose handle mark 1 holds and reads the
/// child's memory at once: 1 in mark 0 when the notification came, what
/// the child returned in mark 2 and its quota but what it uses in mark 3.
/// Ends afterwards.
extern "C" fn watch_exit(h: u64) -> ! {
    let exits = Handle::<Channel>::from_raw(abi::Handle(h));
    let got = sys::receive(&exits);
    let child = Handle::<Process>::from_raw(abi::Handle(mark(1)));
    if let Ok(m) = sys::process_memory(&child) {
        MARKS[2].store(m.returned, Relaxed);
        MARKS[3].store(m.quota - m.used, Relaxed);
    }
    MARKS[0].store(u64::from(got == Ok(exit_notice(CHILD))), Relaxed);
    sys::thread_exit()
}

/// The exit notification carries the label of the handle process_create
/// took as x3 (spec 7.9): a copy with a label gives it, the channel's
/// handle with none gives 0; the source is «exit», bit 0, count 1.
fn exit_notice_carries_the_label() -> Outcome {
    let (exits, name) = exit_channel()?;
    let labelled = heard_child(&name, QUIET, LOW)?;
    let plain = heard_child(&exits, QUIET, LOW)?;
    let killed = [sys::process_kill(&labelled), sys::process_kill(&plain)];
    let first = sys::try_receive(&exits);
    let second = take_one(&exits);
    close(labelled)?;
    close(plain)?;
    close(exits)?;
    close(name)?;
    check(killed.iter().all(Result::is_ok), "process_kill failed")?;
    check(
        first == Ok(exit_notice(CHILD)),
        "the exit notification did not carry the label of x3",
    )?;
    check(
        second == Ok(exit_notice(0)),
        "the exit notification through a handle with no label did not carry 0",
    )
}

/// x3 of process_create is a channel with NOTIFY (spec 11, 13.3): a copy
/// without NOTIFY fails with ACCESS_DENIED, a process with WRONG_TYPE, a
/// closed handle with BAD_HANDLE, a channel that closed with PEER_CLOSED;
/// each changes x0 alone, and no child is made.
fn exit_channel_needs_notify() -> Outcome {
    let c = channel(QUIET)?;
    let receive_only = copy(&c, Rights::RECEIVE)?;
    let shut = channel(QUIET)?;
    let left = copy(&shut, Rights::NOTIFY)?;
    let gone = shut.raw();
    close(shut)?;
    let before = sys::process_handles(&init::PROCESS);
    let refused = [
        (receive_only.raw(), Error::AccessDenied),
        (init::PROCESS.raw(), Error::WrongType),
        (gone, Error::BadHandle),
        (left.raw(), Error::PeerClosed),
    ]
    .map(|(h, error)| {
        let x = create_regs(h, QUIET.into(), abi::Handle::INVALID);
        failed(raw_create(x), x, error)
    });
    let after = sys::process_handles(&init::PROCESS);
    close(receive_only)?;
    close(left)?;
    close(c)?;
    check(
        refused.iter().all(|&ok| ok),
        "x3 that is no open channel with NOTIFY did not fail alone",
    )?;
    check(
        before.is_ok() && after == before,
        "a child of a call that failed has a handle",
    )
}

/// x4 of process_create, the priority of the exit notification (spec 7.9,
/// 11): 1-63 with an exit channel, 63, init's ceiling, included, and
/// exactly 0 without one; anything else fails with INVALID_ARGS and
/// changes x0 alone. A receiver at LOW waits on the exit channel; the
/// end of a child that init kills comes at NOTICE and wakes it above init
/// before process_kill returns. x4 above the caller's own ceiling fails
/// with ACCESS_DENIED alone after the handles in x3 and x5, and x3 on a
/// channel that closed fails with PEER_CLOSED only under that ceiling: 31
/// and 30 in a child under ceiling 30 (`caller_ceiling`).
fn exit_priority_under_the_ceiling() -> Outcome {
    let (c, r) = waiting_receiver(QUIET)?;
    let name = session(&c, Rights::NOTIFY, CHILD, QUIET)?;
    let n = name.raw();
    let refused = [
        (n, 0),
        (abi::Handle::INVALID, u64::from(QUIET)),
        (n, abi::PRIORITY_LEVELS.into()),
        (n, 0x100 | u64::from(QUIET)),
    ]
    .map(|(x3, x4)| {
        let x = create_regs(x3, x4, abi::Handle::INVALID);
        failed(raw_create(x), x, Error::InvalidArgs)
    });
    let top = heard_child(&name, abi::PRIORITY_LEVELS - 1, LOW);
    let heard = heard_child(&name, NOTICE, LOW)?;
    let waited = mark(0);
    let killed = sys::process_kill(&heard);
    let ran = mark(0);
    let_run()?;
    close(r)?;
    close(c)?;
    close(heard)?;
    let highest = top.is_ok();
    if let Ok(top) = top {
        close(top)?;
    }
    close(name)?;
    check(
        refused.iter().all(|&ok| ok),
        "a priority outside 1-63 with x3, or one without x3, was taken",
    )?;
    check(
        highest,
        "the exit priority 63 under init's ceiling was refused",
    )?;
    check(waited == 0, "the receiver did not wait")?;
    check(
        killed.is_ok() && ran == 1,
        "the receiver did not run at the exit notification's priority before process_kill returned",
    )?;
    caller_ceiling(Checked::ExitChannel)
}

/// A child that fails leaves the start channel with init (spec 13.3): a
/// quota of a page falls short at entry 0 of the child's table, NO_MEMORY,
/// and x0 alone changes; the handle x5 named still works, and init has its
/// quota back. With init's table full the call fails with LIMIT_REACHED
/// before it makes anything (spec 11), x0 alone, and x5 stays as well. The
/// exit channel of the failed calls gets its slot back: the channel goes
/// afterwards with no source left.
fn failed_create_keeps_the_start_handle() -> Outcome {
    let c = channel(QUIET)?;
    let exit = copy(&c, Rights::NOTIFY)?;
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let before = used();
    let mut x = create_regs(exit.raw(), QUIET.into(), c.raw());
    x[0] = PAGE as u64;
    let after = raw_create(x);
    let back = used();
    let n = fill_table(0)?;
    let y = create_regs(exit.raw(), QUIET.into(), c.raw());
    let full = raw_create(y);
    empty_table(n)?;
    let posted = sys::notify(&c, 1);
    let got = take_one(&c);
    let kept = c.close();
    // The channel goes now: it holds no source but its slot of label 0.
    close(exit)?;
    check(
        failed(after, x, Error::NoMemory),
        "a child with a quota of a page did not fail with NO_MEMORY alone",
    )?;
    check(
        failed(full, y, Error::LimitReached),
        "a child with init's table full did not fail with LIMIT_REACHED alone",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)) && kept.is_ok(),
        "init lost the start channel of a child that failed",
    )?;
    check(
        before.is_ok() && back == before,
        "a child that failed kept init's quota",
    )
}

/// x5 of process_create moves a channel handle with TRANSFER into entry 0
/// of the child's table (spec 13.3): init's handle is gone (BAD_HANDLE),
/// the child's table holds one live handle, and the channel lives on with
/// it, since it carried RECEIVE: a copy of init with NOTIFY notifies. The
/// child's end lets that handle go, and the channel closes: notify then
/// fails with PEER_CLOSED. The child's exit channel closes before its end
/// with nothing queued; the notification is lost, and the child's shell
/// goes once init closes its handle.
fn start_channel_moves_into_the_child() -> Outcome {
    let c = channel(QUIET)?;
    let n = copy(&c, Rights::NOTIFY)?;
    let (exits, name) = exit_channel()?;
    let moved = c.raw();
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let before = used();
    let made = sys::process_create_with(CHILD_QUOTA, 16, LOW, Some((&name, QUIET)), Some(c));
    let Ok(child) = made else {
        close(n)?;
        close(exits)?;
        close(name)?;
        return Err("process_create with a start channel failed");
    };
    // The exit channel closes with nothing queued: the stage Close has
    // nothing to take, and the exit notification finds it closed.
    close(exits)?;
    let gone = Handle::<Channel>::from_raw(moved).close();
    let table = sys::process_handles(&child);
    let open = sys::notify(&n, 1);
    let killed = sys::process_kill(&child);
    let shut = sys::notify(&n, 1);
    close(child)?;
    let back = used();
    close(n)?;
    close(name)?;
    check(
        before.is_ok() && back == before,
        "the child's shell stayed after its exit notification met a closed channel",
    )?;
    check(gone == Err(Error::BadHandle), "init kept the start channel")?;
    check(
        table.is_ok_and(|t| t.live == 1),
        "the child's table does not hold the start channel",
    )?;
    check(
        open.is_ok() && killed.is_ok() && shut == Err(Error::PeerClosed),
        "the channel did not live with the child's handle and close with it",
    )
}

/// x5 needs TRANSFER (spec 11): a copy without it fails with ACCESS_DENIED
/// and changes x0 alone, and the handle stays init's.
fn start_channel_needs_transfer() -> Outcome {
    let c = channel(QUIET)?;
    let kept = copy(&c, Rights::NOTIFY | Rights::RECEIVE)?;
    let x = create_regs(abi::Handle::INVALID, 0, kept.raw());
    let after = raw_create(x);
    let posted = sys::notify(&kept, 1);
    let got = take_one(&kept);
    close(kept)?;
    close(c)?;
    check(
        failed(after, x, Error::AccessDenied),
        "x5 without TRANSFER did not fail with ACCESS_DENIED alone",
    )?;
    check(
        posted.is_ok() && got == Ok(unlabeled(1, 1)),
        "the handle without TRANSFER did not stay init's",
    )
}

/// x5 names a channel (spec 11, 13.3): a process fails with WRONG_TYPE, a
/// closed handle with BAD_HANDLE, and x3 is looked at first.
fn start_handle_must_be_a_channel() -> Outcome {
    let c = channel(QUIET)?;
    let gone = c.raw();
    close(c)?;
    let own = init::PROCESS.raw();
    let refused = [
        (abi::Handle::INVALID, 0, own, Error::WrongType),
        (abi::Handle::INVALID, 0, gone, Error::BadHandle),
        (gone, u64::from(QUIET), own, Error::BadHandle),
    ]
    .map(|(x3, x4, x5, error)| {
        let x = create_regs(x3, x4, x5);
        failed(raw_create(x), x, error)
    });
    check(
        refused.iter().all(|&ok| ok),
        "x5 that is no live channel did not fail alone, or came before x3",
    )
}

/// Spec 15.2 (refusals): one handle, a copy with a label, NOTIFY and
/// TRANSFER, is both x3 and x5 (spec 13.3): it moves into the child, and
/// its label names the child's end. When init kills the child, the
/// child's table lets the copy go, which posts CLIENT_GONE with the label
/// (spec 5.3), and after the child's stage Quota the exit notification
/// comes with the same label.
fn client_gone_when_the_child_dies() -> Outcome {
    let exits = channel(QUIET)?;
    let name = session(&exits, Rights::NOTIFY | Rights::TRANSFER, CHILD, QUIET)?;
    let x = create_regs(name.raw(), QUIET.into(), name.raw());
    let after = raw_create(x);
    let made = after[0] == 0 && after[2..] == x[2..];
    let moved = name.close();
    let child = Handle::<Process>::from_raw(abi::Handle(after[1]));
    let killed = sys::process_kill(&child);
    let got = [(); 3].map(|()| sys::try_receive(&exits));
    if made {
        close(child)?;
    }
    close(exits)?;
    check(made, "process_create with one handle as x3 and x5 failed")?;
    check(
        moved == Err(Error::BadHandle),
        "the copy did not move into the child",
    )?;
    check(
        killed.is_ok()
            && got
                == [
                    Ok(labelled(CHILD, CLIENT_GONE, 1)),
                    Ok(exit_notice(CHILD)),
                    Err(Error::WouldBlock),
                ],
        "the child's end did not post CLIENT_GONE and then the exit notification with the label",
    )
}

/// A timer on `c` at QUIET, whose notifications never lift init above its
/// threads (spec 6.6).
fn timer(c: &Handle<Channel>) -> Result<Handle<Timer>, &'static str> {
    timer_at(c, QUIET)
}

/// A timer on `c` whose slot has `priority`: it fires at that level, ahead
/// of the threads below it and after those above (spec 10), so a thread
/// whose wait it bounds gives it its own level at least.
fn timer_at(c: &Handle<Channel>, priority: u8) -> Result<Handle<Timer>, &'static str> {
    sys::timer_create(c, priority).map_err(|_| "timer_create failed")
}

/// timer_create with raw registers.
fn raw_timer_create(x: Regs) -> Regs {
    // SAFETY: timer_create only reads its registers.
    unsafe { sys::raw::<{ Call::TimerCreate.number() }>(x) }
}

fn clock_now() -> Result<u64, &'static str> {
    sys::clock_now().map_err(|_| "clock_now failed")
}

fn arm(t: &Handle<Timer>, deadline: u64) -> Outcome {
    sys::timer_set(t, deadline).map_err(|_| "timer_set failed")
}

/// Spins until the counter, in nanoseconds, passed `ns`.
fn spin_past(ns: u64) {
    while time::ticks_to_ns(time::now()) <= ns {}
}

/// `count` expiries of a timer made through a handle with `label`: bit 0.
fn expiry(label: u64, count: u32) -> Received {
    Received::Notification {
        source: Source::Timer,
        label,
        bits: 1,
        count,
    }
}

/// Spec 15.2 (time): a program reads the counter itself (CNTVCT_EL0,
/// spec 10), and clock_now between two such readings returns nanoseconds
/// between theirs, rounded down as rt::time converts them; it changes x0
/// and x1 alone.
fn clock_now_follows_the_counter() -> Outcome {
    let x = marked();
    let before = time::now();
    // SAFETY: clock_now reads no register.
    let after = unsafe { sys::raw::<{ Call::ClockNow.number() }>(x) };
    let later = time::now();
    let typed = sys::clock_now();
    check(
        after[0] == 0 && after[2..] == x[2..],
        "clock_now failed or changed registers past x1",
    )?;
    check(
        (time::ticks_to_ns(before)..=time::ticks_to_ns(later)).contains(&after[1]),
        "clock_now is not between two readings of the counter",
    )?;
    check(typed.is_ok_and(|ns| ns >= after[1]), "clock_now went back")
}

/// timer_create takes a channel with RECEIVE (spec 6.5, 10): a timer is a
/// bound on its creator's own wait, and the slots of the channel and the
/// priorities that lift its receivers are the receiver's. A priority
/// outside 1-63 fails with INVALID_ARGS before the handle is looked at, a
/// bad handle with BAD_HANDLE, a handle to another kind with WRONG_TYPE, a
/// copy with NOTIFY alone with ACCESS_DENIED; each changes x0 alone, and so
/// does a priority above the caller's own ceiling, ACCESS_DENIED: 31 in a
/// child under ceiling 30 (`caller_ceiling`). A copy with RECEIVE and a
/// label makes a timer whose expiries carry the label.
fn timer_needs_receive() -> Outcome {
    let c = channel(QUIET)?;
    let notify = copy(&c, Rights::NOTIFY)?;
    let labelled = session(&c, Rights::RECEIVE, TIMED, QUIET)?;
    let cases = [
        (abi::Handle::INVALID, 0, Error::InvalidArgs),
        (c.raw(), 64, Error::InvalidArgs),
        (c.raw(), 0x100 | u64::from(QUIET), Error::InvalidArgs),
        (abi::Handle::INVALID, QUIET.into(), Error::BadHandle),
        (init::PROCESS.raw(), QUIET.into(), Error::WrongType),
        (notify.raw(), QUIET.into(), Error::AccessDenied),
    ];
    let refused = cases.map(|(h, priority, error)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, priority]);
        failed(raw_timer_create(x), x, error)
    });
    let t = sys::timer_create(&labelled, QUIET);
    let fired = t
        .as_ref()
        .map_err(|&e| e)
        .and_then(|t| sys::timer_set(t, 0));
    let got = sys::try_receive(&c);
    if let Ok(t) = t {
        close(t)?;
    }
    close(labelled)?;
    close(notify)?;
    close(c)?;
    check(
        refused.iter().all(|&ok| ok),
        "timer_create took a channel without RECEIVE or a bad argument, or changed more than x0",
    )?;
    check(
        fired.is_ok() && got == Ok(expiry(TIMED, 1)),
        "a timer made through a labelled copy did not carry the label",
    )?;
    caller_ceiling(Checked::TimerCreate)
}

/// timer_set(x0 timer with MANAGE, x1 deadline) and timer_cancel(x0 timer
/// with MANAGE) check their handle (spec 10, 11) and change x0 alone on
/// an error: a closed handle fails with BAD_HANDLE, a handle to another
/// kind with WRONG_TYPE, a copy without MANAGE with ACCESS_DENIED.
/// timer_set on a timer whose channel closed fails with PEER_CLOSED and
/// changes x0 alone as well; timer_cancel still takes the timer.
fn timer_set_and_cancel_check_their_handles() -> Outcome {
    let gone = closed_handle()?;
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let seen = copy(&t, Rights::DUPLICATE)?;
    let refused = timer_handle_cases(gone, c.raw().0, seen.raw().0);
    close(seen)?;
    let armed = clock_now().and_then(|now| arm(&t, now + 1_000_000_000));
    // The last handle with RECEIVE goes: the channel closes (spec 6.8).
    close(c)?;
    let closed = x0_alone::<{ Call::TimerSet.number() }>(&[t.raw().0, 0], Error::PeerClosed.code());
    let cancelled = sys::timer_cancel(&t);
    close(t)?;
    armed?;
    check(
        refused,
        "a closed handle, a handle to another kind or a copy without MANAGE did not fail alone",
    )?;
    check(
        closed,
        "timer_set on a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(cancelled.is_ok(), "timer_cancel on a closed channel failed")
}

fn timer_handle_cases(gone: u64, channel: u64, seen: u64) -> bool {
    const SET: u16 = Call::TimerSet.number();
    const CANCEL: u16 = Call::TimerCancel.number();
    let resource = init::RESOURCE.raw().0;
    [
        x0_alone::<SET>(&[gone, 0], Error::BadHandle.code()),
        x0_alone::<CANCEL>(&[gone], Error::BadHandle.code()),
        x0_alone::<SET>(&[resource, 0], Error::WrongType.code()),
        x0_alone::<CANCEL>(&[channel], Error::WrongType.code()),
        x0_alone::<SET>(&[seen, 0], Error::AccessDenied.code()),
        x0_alone::<CANCEL>(&[seen], Error::AccessDenied.code()),
    ]
    .iter()
    .all(|&ok| ok)
}

/// Spec 15.2 (time): a timer on a channel and receive make a wait with a
/// bound (spec 6.1, 10). Init waits on an empty channel whose timer fires
/// 1 ms from now and wakes with the timer's notification, bit 0 once, not
/// before the deadline; nothing else comes.
fn timer_bounds_a_wait() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let deadline = clock_now()? + 1_000_000;
    let set = arm(&t, deadline);
    let got = sys::receive(&c);
    let woke = clock_now();
    let rest = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    set?;
    check(
        got == Ok(expiry(0, 1)),
        "the wait did not end with the timer's notification",
    )?;
    check(
        woke.is_ok_and(|ns| ns >= deadline),
        "the wait ended before the timer's deadline",
    )?;
    check(
        rest == Err(Error::WouldBlock),
        "something came after the timer",
    )
}

/// Spec 15.2 (time): what came before the bound ends the wait first.
/// init notifies the channel, arms the timer 20 ms on and waits: the wait
/// ends at once with the notification, init cancels the timer, and once
/// the deadline passed nothing more comes.
fn notification_before_the_timer_comes_first() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let notified = sys::notify(&c, NOTIFIED);
    let deadline = clock_now()? + 20_000_000;
    let set = arm(&t, deadline);
    let got = sys::receive(&c);
    let cancelled = sys::timer_cancel(&t);
    spin_past(deadline);
    let rest = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    set?;
    check(
        notified.is_ok() && cancelled.is_ok(),
        "notify or timer_cancel failed",
    )?;
    check(
        got == Ok(unlabeled(NOTIFIED, 1)),
        "the notification before the deadline did not come first",
    )?;
    check(rest == Err(Error::WouldBlock), "the cancelled timer fired")
}

/// Spec 15.2 (time): a deadline that passed fires in timer_set itself
/// (spec 10). Right after timer_set with 0, with the time clock_now gave,
/// and with a past deadline for an armed timer, the timer's notification
/// is there, bit 0 once each time.
fn timer_in_the_past_fires_at_once() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = past_deadlines(&c, &t);
    close(t)?;
    close(c)?;
    result
}

fn past_deadlines(c: &Handle<Channel>, t: &Handle<Timer>) -> Outcome {
    let now = clock_now()?;
    for (armed, past) in [(false, 0), (false, now), (true, now)] {
        if armed {
            arm(t, now + 1_000_000_000)?;
        }
        arm(t, past)?;
        check(
            sys::try_receive(c) == Ok(expiry(0, 1)),
            "a deadline in the past did not fire at once",
        )?;
    }
    check(
        sys::try_receive(c) == Err(Error::WouldBlock),
        "a timer set into the past fired once more",
    )
}

/// timer_set of an armed timer moves it (spec 10): armed a second away and
/// then 1 ms away, it fires at the nearer deadline, long before the far
/// one; armed 10 ms away and then a second away, it does not fire at the
/// nearer one, which a stall of the host cannot pass before the call.
fn timer_set_moves_the_deadline() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = moves(&c, &t);
    close(t)?;
    close(c)?;
    result
}

fn moves(c: &Handle<Channel>, t: &Handle<Timer>) -> Outcome {
    let now = clock_now()?;
    let (near, far) = (now + 1_000_000, now + 1_000_000_000);
    arm(t, far)?;
    arm(t, near)?;
    let got = sys::receive(c);
    let at = clock_now()?;
    check(
        got == Ok(expiry(0, 1)) && (near..far).contains(&at),
        "the timer did not move to the nearer deadline",
    )?;
    let now = clock_now()?;
    let (near, far) = (now + 10_000_000, now + 1_000_000_000);
    arm(t, near)?;
    arm(t, far)?;
    spin_past(near + 1_000_000);
    let rest = sys::try_receive(c);
    sys::timer_cancel(t).map_err(|_| "timer_cancel failed")?;
    check(
        rest == Err(Error::WouldBlock),
        "the timer fired at the deadline it moved away from",
    )
}

/// timer_cancel leaves what the timer posted (spec 10): a timer that fired
/// in timer_set and is cancelled afterwards still has its notification
/// waiting; cancelling a timer that is not armed is no error.
fn cancel_keeps_posted_bits() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let fired = arm(&t, 0);
    let cancelled = sys::timer_cancel(&t);
    let got = sys::try_receive(&c);
    let again = sys::timer_cancel(&t);
    close(t)?;
    close(c)?;
    fired?;
    check(cancelled.is_ok() && again.is_ok(), "timer_cancel failed")?;
    check(
        got == Ok(expiry(0, 1)),
        "timer_cancel took back what the timer posted",
    )
}

/// Spec 15.2 (time): a timer never fires before its deadline (spec 10).
/// For deadlines 200 µs away at 16 offsets a nanosecond apart, on the
/// ticks of the counter and between them, init wakes with the timer's
/// notification at a time clock_now gives no earlier than the deadline.
fn timer_never_fires_early() -> Outcome {
    let c = channel(QUIET)?;
    let t = timer(&c)?;
    let result = (0..16).try_for_each(|offset| {
        let deadline = clock_now()? + 200_000 + offset;
        arm(&t, deadline)?;
        let got = sys::receive(&c);
        let woke = clock_now()?;
        check(
            got == Ok(expiry(0, 1)) && woke >= deadline,
            "a timer fired before its deadline",
        )
    });
    close(t)?;
    close(c)?;
    result
}

/// Spec 15.2 (priorities, time): a timer fires at the priority of its slot
/// (spec 10). W at init's level waits on a channel of that level whose
/// timer's slot has LEVEL, H at HIGH on one of its level whose timer's
/// slot has HIGH, both timers for one deadline; S, FIFO at SPIN between
/// them, spins until H came back from its wait and notes whether W did.
/// Init lets them run: the firing of HIGH comes ahead of S and wakes H,
/// the firing of LEVEL waits until S ends, and only then W, whose level is
/// above S, gets its expiry. Only the priorities order them; a second on
/// the counter only keeps S from spinning forever.
fn timer_fires_at_its_slot_priority() -> Outcome {
    const SPIN: u8 = 15;
    reset_results();
    let low = channel(TEST_PRIORITY)?;
    let high = channel(HIGH)?;
    let timers = [timer_at(&low, LEVEL)?, timer_at(&high, HIGH)?];
    HANDLES[0].store(low.raw().0, Relaxed);
    HANDLES[1].store(high.raw().0, Relaxed);
    let h = spawn(1, receive_then_look, 1, HIGH, Policy::Fifo)?;
    let w = spawn(0, receive_then_look, 0, TEST_PRIORITY, Policy::Fifo)?;
    // W, behind init at its level, waits once init yields to it.
    let yielded = sys::yield_now();
    let s = spawn(2, look_once_ended, 1, SPIN, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| {
        let at = now + 1_000_000;
        timers.iter().try_for_each(|t| arm(t, at))
    });
    let ran = armed.and_then(|()| let_run());
    for t in [h, w, s] {
        close(t)?;
    }
    for t in timers {
        close(t)?;
    }
    close(low)?;
    close(high)?;
    ran?;
    check(yielded.is_ok(), "yield failed")?;
    check(
        ended(0) && ended(1) && result(0)[0] == 0 && result(1)[0] == 0,
        "a timer's expiry did not come",
    )?;
    check(
        result(2)[..2] == [1, 0],
        "the timer of W fired above its slot's priority, or that of H below",
    )
}

/// Spins until the thread in `slot` came back from its call, or a second
/// passed, and leaves in `result` of slot 2 whether it did and whether the
/// thread in slot 0 did by then; ends.
extern "C" fn look_once_ended(slot: u64) -> ! {
    let end = time::now() + time::ns_to_ticks(1_000_000_000);
    while !ended(slot as usize) && time::now() < end {}
    record(
        2,
        &[ENDED[slot as usize].load(Relaxed), ENDED[0].load(Relaxed)],
    );
    sys::thread_exit()
}

/// Spec 15.2 (notifications): a process pays for abi::MAX_TIMERS timers at
/// most (spec 10). With 64 made, the next timer_create fails with
/// LIMIT_REACHED and changes x0 alone; once one of them went, another
/// fits.
fn timer_limit_is_64() -> Outcome {
    let c = channel(QUIET)?;
    let mut timers = [const { None }; abi::MAX_TIMERS as usize];
    let made = timers.iter_mut().try_for_each(|slot| {
        *slot = Some(timer(&c)?);
        Ok(())
    });
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, QUIET.into()]);
    let after = raw_timer_create(x);
    let freed = timers[0].take().map(close);
    let again = sys::timer_create(&c, QUIET);
    let remade = again.is_ok();
    if let Ok(t) = again {
        close(t)?;
    }
    for t in timers.into_iter().flatten() {
        close(t)?;
    }
    close(c)?;
    made?;
    check(
        failed(after, x, Error::LimitReached),
        "a timer past 64 was made, or the call changed more than x0",
    )?;
    check(
        freed == Some(Ok(())) && remade,
        "no new timer fit once one went",
    )
}

// Memory objects (spec 7.3, 7.7).

/// A memory object of `pages` pages.
fn memory_object(pages: u64) -> Result<Handle<Memory>, &'static str> {
    sys::mem_create(pages * PAGE as u64).map_err(|_| "mem_create failed")
}

/// mem_create(x0 size, x1 flags) checks its values, the size and then the
/// flags, of which none is known (spec 7.3, 11), and changes x0 alone on an
/// error: a size of 0, off whole pages, past abi::MAX_MEMORY or with bits
/// past it, and any flag fail with INVALID_ARGS. A good call changes x0 and
/// x1 alone: a handle with abi::MEMORY_RIGHTS, which a copy with all of
/// them shows and one with MANAGE does not get. The caller's resources are
/// kernel tests (mem_create_over_the_quota_is_no_memory).
fn mem_create_checks_its_arguments() -> Outcome {
    const N: u16 = Call::MemCreate.number();
    let page = PAGE as u64;
    let values = [
        (0, 0),
        (1, 0),
        (page - 1, 0),
        (page + 8, 0),
        (abi::MAX_MEMORY + page, 0),
        (1 << 40, 0),
        (u64::MAX, 0),
        (page, 1),
        (page, 1 << 63),
        (0, 1),
    ]
    .into_iter()
    .all(|(size, flags)| x0_alone::<N>(&[size, flags], Error::InvalidArgs.code()));
    check(
        values,
        "a bad size or a flag did not fail with INVALID_ARGS alone",
    )?;
    let mut x = marked();
    x[..2].copy_from_slice(&[2 * page, 0]);
    // SAFETY: mem_create only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    check(
        after[0] == 0 && after[1] != 0 && after[2..] == x[2..],
        "a good mem_create failed or changed registers past x1",
    )?;
    let m: Handle<Memory> = Handle::from_raw(abi::Handle(after[1]));
    let all = sys::handle_duplicate(&m, abi::MEMORY_RIGHTS).map(close);
    let more = sys::handle_duplicate(&m, abi::MEMORY_RIGHTS | Rights::MANAGE).map(close);
    close(m)?;
    check(
        all == Ok(Ok(())) && more == Err(Error::AccessDenied),
        "the handle of mem_create does not carry MEMORY_RIGHTS and no more",
    )
}

/// mem_create takes the whole object before it returns (spec 7.3): right
/// afterwards MEMORY counts every page of an object of 600 pages as owned,
/// init's used memory grew by the pages and the three nodes of their list
/// and by nothing else, and the free frames fell by the pages at least.
/// An object made and closed first leaves a free place in init's pool of
/// memory objects, so that the call charges no page of the pool.
fn mem_create_takes_the_whole_object_at_once() -> Outcome {
    const PAGES: u64 = 600;
    close(memory_object(1)?)?;
    let before = counts()?;
    let m = memory_object(PAGES)?;
    let info = sys::memory_info(&m);
    let after = counts()?;
    check(
        info == Ok(MemoryInfo {
            size: PAGES * PAGE as u64,
            pages: PAGES,
            mappings: 0,
        }),
        "MEMORY does not count every page of a new object as owned",
    )?;
    check(
        after.0 == before.0 + (PAGES + 3) * PAGE as u64,
        "init's used memory did not grow by the pages and the nodes of the new object",
    )?;
    check(
        before.1.saturating_sub(after.1) >= PAGES,
        "the free frames did not fall by the pages of the new object",
    )?;
    close(m)
}

/// The cleanup of a memory object runs at init's level before its
/// handle_close returns (spec 7.7): right after the close of an object of
/// 256 pages, whose frames go back in portions, init's used memory, the
/// free frames and the pages of kernel pools are what they were before
/// mem_create. An object made and closed first leaves a free place in
/// init's pool of memory objects.
fn closed_object_gives_its_frames_back() -> Outcome {
    close(memory_object(1)?)?;
    let before = counts()?;
    close(memory_object(256)?)?;
    check(
        counts()? == before,
        "the frames of a closed object were not back when handle_close returned",
    )
}

/// object_info(MEMORY) takes a memory object's handle with no right needed
/// and returns its size in bytes, the pages whose frames it owns, all of a
/// new object, and its mappings, none yet, in x1-x3, and nothing past them
/// (spec 11). A process and the system resource are WRONG_TYPE for it, a
/// memory object is WRONG_TYPE for the kinds of a process and for
/// KERNEL_STATS, and a closed handle is BAD_HANDLE; x0 alone changes.
fn memory_info_reports_size_pages_and_mappings() -> Outcome {
    let m = memory_object(3)?;
    let bare = copy(&m, Rights::NONE)?;
    let gone = closed_handle()?;
    let result = memory_info_cases(bare.raw().0, gone);
    close(bare)?;
    close(m)?;
    result
}

fn memory_info_cases(bare: u64, gone: u64) -> Outcome {
    const N: u16 = Call::ObjectInfo.number();
    let memory = abi::INFO_MEMORY;
    let mut x = marked();
    x[..3].copy_from_slice(&[bare, memory, 0]);
    // SAFETY: object_info only reads its registers.
    let after = unsafe { sys::raw::<N>(x) };
    let three = MemoryInfo {
        size: 3 * PAGE as u64,
        pages: 3,
        mappings: 0,
    };
    let wrong = [
        (init::PROCESS.raw().0, memory, Error::WrongType),
        (init::RESOURCE.raw().0, memory, Error::WrongType),
        (bare, abi::INFO_PROCESS_STATE, Error::WrongType),
        (bare, abi::INFO_PROCESS_MEMORY, Error::WrongType),
        (bare, abi::INFO_KERNEL_STATS, Error::WrongType),
        (gone, memory, Error::BadHandle),
    ]
    .into_iter()
    .all(|(h, kind, error)| x0_alone::<N>(&[h, kind, 0], error.code()));
    check(
        after[0] == 0 && after[1..4] == three.to_words() && after[4..] == x[4..],
        "MEMORY through a copy with no rights did not give the size, the pages and no mapping in x1-x3 alone",
    )?;
    check(
        wrong,
        "a handle of another kind or a closed one did not fail alone",
    )
}

// Mappings (spec 6.2, 7.4, 7.7).

/// Where the tests of mappings show their objects: a gigabyte of init's
/// space far from its program, its stack and its buffers.
const WINDOW: usize = 0x40_0000_0000;
/// The object of the tests of busy mappings: 64 MiB, whose mapping takes
/// 512 portions, and the period of the timer that wakes a thread until it
/// finds the mapping in the middle of them: long enough for the mapping to
/// go on between two wakes under -icount.
const BIG: u64 = 64 << 20;
const PROBE_PERIOD_NS: u64 = 200_000;
/// The timer of the tests of busy mappings, for the thread it wakes.
static PROBE_TIMER: AtomicU64 = AtomicU64::new(0);
/// Init's own mappings: its code, its read-only data, its data and its
/// stack, which the kernel made (spec 13.3), and the boot image and the
/// page of marks of its children (`prepare`).
const INIT_MAPPINGS: usize = 6;
/// `mov x0, #42` and `ret`: a function that returns 42.
const RETURN_42: [u32; 2] = [0xD280_0540, 0xD65F_03C0];

/// mem_map of `len` bytes of `m` from `offset` at `addr` of init.
fn map(m: &Handle<Memory>, offset: u64, len: u64, addr: usize, access: Access) -> Outcome {
    sys::mem_map(&init::PROCESS, m, offset, len, addr, access).map_err(|_| "mem_map failed")
}

/// mem_unmap of the mapping of init that is `len` bytes from `addr`.
fn unmap(addr: usize, len: u64) -> Outcome {
    // SAFETY: the tests unmap only their own windows, which nothing else
    // uses.
    unsafe { sys::mem_unmap(&init::PROCESS, addr, len) }.map_err(|_| "mem_unmap failed")
}

/// The tables and the table of mappings a page at `addr` needs are made:
/// a page of an object is mapped there and unmapped, and the object goes.
/// Tables stay until the space goes (spec 7.5), so a test that counts
/// memory afterwards sees none of them come.
fn warm(addr: usize) -> Outcome {
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, addr, Access::Read)?;
    unmap(addr, PAGE as u64)?;
    close(m)
}

/// A child that ended, killed.
fn ended_child() -> Result<Handle<Process>, &'static str> {
    let c = child(LEVEL)?;
    sys::process_kill(&c).map_err(|_| "process_kill failed")?;
    Ok(c)
}

/// mem_map(x0 process with MANAGE, x1 memory object, x2 offset, x3 length,
/// x4 address, x5 access) checks in the order of spec 11 and changes x0
/// alone on an error: an offset, a length or an address off whole pages, a
/// length of 0, a range past the lower half and an access other than R, RW
/// or RX fail with INVALID_ARGS, through closed handles too; then x0 (a
/// closed handle BAD_HANDLE, a memory object WRONG_TYPE, a copy without
/// MANAGE ACCESS_DENIED), then x1 (BAD_HANDLE, a process WRONG_TYPE, a
/// copy without MAP_READ ACCESS_DENIED); a process that ended fails with
/// BAD_STATE before its range is looked at; a range past the object and
/// one over a mapping fail with INVALID_ARGS. A good call changes x0
/// alone. The limit of mappings is mapping_limit_is_64; the quota of the
/// process, which pays for the tables, is a kernel test
/// (map_that_does_not_fit_maps_nothing).
fn mem_map_checks_its_arguments() -> Outcome {
    let m = memory_object(4)?;
    let no_read = copy(&m, Rights::MAP_WRITE | Rights::MAP_EXEC)?;
    let no_manage = copy(&init::PROCESS, Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    let result = map_cases(&m, no_read.raw().0, no_manage.raw().0, ended.raw().0, gone);
    close(no_read)?;
    close(no_manage)?;
    close(ended)?;
    let unmapped = unmap(WINDOW, PAGE as u64);
    close(m)?;
    result.and(unmapped)
}

fn map_cases(m: &Handle<Memory>, no_read: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemMap.number();
    let (own, mem) = (init::PROCESS.raw().0, m.raw().0);
    let (page, at, r) = (PAGE as u64, WINDOW as u64, Access::Read.raw());
    let cases = [
        ([own, mem, 8, page, at, r], Error::InvalidArgs),
        ([own, mem, 0, 0, at, r], Error::InvalidArgs),
        ([own, mem, 0, page + 8, at, r], Error::InvalidArgs),
        ([own, mem, 0, page, at + 8, r], Error::InvalidArgs),
        (
            [own, mem, 0, 2 * page, LOWER_END - page, r],
            Error::InvalidArgs,
        ),
        ([own, mem, 0, page, at, 6], Error::InvalidArgs),
        ([gone, gone, 8, page, at, r], Error::InvalidArgs),
        ([gone, mem, 0, page, at, r], Error::BadHandle),
        ([mem, mem, 0, page, at, r], Error::WrongType),
        ([no_manage, gone, 0, page, at, r], Error::AccessDenied),
        ([own, gone, 0, page, at, r], Error::BadHandle),
        ([own, own, 0, page, at, r], Error::WrongType),
        ([own, no_read, 0, page, at, r], Error::AccessDenied),
        ([ended, mem, 3 * page, 2 * page, at, r], Error::BadState),
        ([own, mem, 3 * page, 2 * page, at, r], Error::InvalidArgs),
        (
            [own, mem, u64::MAX - page + 1, page, at, r],
            Error::InvalidArgs,
        ),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    check(
        cases,
        "a bad mem_map did not fail alone as spec 11 orders it",
    )?;
    check(
        x0_alone::<N>(&[own, mem, 3 * page, page, at, r], 0),
        "a good mem_map failed or changed registers past x0",
    )?;
    check(
        x0_alone::<N>(&[own, mem, 0, page, at, r], Error::InvalidArgs.code()),
        "a mapping over another did not fail with INVALID_ARGS alone",
    )
}

/// W^X in one mapping (spec 7.4): of the access values only R (1), RW (3)
/// and RX (5) map; 0, W alone, X alone, W with X, the three together and
/// the bits past them fail with INVALID_ARGS alone.
fn map_access_is_r_rw_or_rx() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (own, mem, page, at) = (init::PROCESS.raw().0, m.raw().0, PAGE as u64, WINDOW as u64);
    let refused = [0, 2, 4, 6, 7, 8, 9, 1 << 32 | 1]
        .into_iter()
        .all(|access| x0_alone::<N>(&[own, mem, 0, page, at, access], Error::InvalidArgs.code()));
    let mut mapped = true;
    for access in [Access::Read, Access::ReadWrite, Access::ReadExec] {
        mapped &= map(&m, 0, page, WINDOW, access).is_ok() && unmap(WINDOW, page).is_ok();
    }
    close(m)?;
    check(
        refused,
        "an access other than R, RW or RX was not refused alone",
    )?;
    check(mapped, "R, RW or RX did not map")
}

/// Each access needs its rights of the object's handle (spec 5.2, 7.4): a
/// copy with MAP_READ alone maps R and fails RW and RX with ACCESS_DENIED
/// alone; one without MAP_EXEC maps RW, one without MAP_WRITE maps RX.
fn map_needs_the_rights_of_its_access() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (read, read_write, read_exec) = (
        copy(&m, Rights::MAP_READ)?,
        copy(&m, Rights::MAP_READ | Rights::MAP_WRITE)?,
        copy(&m, Rights::MAP_READ | Rights::MAP_EXEC)?,
    );
    let (own, page, at) = (init::PROCESS.raw().0, PAGE as u64, WINDOW as u64);
    let denied = [
        (&read, Access::ReadWrite),
        (&read, Access::ReadExec),
        (&read_write, Access::ReadExec),
        (&read_exec, Access::ReadWrite),
    ]
    .into_iter()
    .all(|(h, access)| {
        let args = [own, h.raw().0, 0, page, at, access.raw()];
        x0_alone::<N>(&args, Error::AccessDenied.code())
    });
    let mut mapped = true;
    for (h, access) in [
        (&read, Access::Read),
        (&read_write, Access::ReadWrite),
        (&read_exec, Access::ReadExec),
    ] {
        mapped &= map(h, 0, page, WINDOW, access).is_ok() && unmap(WINDOW, page).is_ok();
    }
    for h in [read, read_write, read_exec, m] {
        close(h)?;
    }
    check(
        denied,
        "an access past the rights of the handle was not refused alone",
    )?;
    check(
        mapped,
        "a handle with the rights of an access did not map it",
    )
}

/// Two mappings of one object show the same frames (spec 7.4): a word
/// written through one reads back through the other, and object_info
/// MEMORY counts both, then none once they went.
fn two_mappings_show_the_same_pages() -> Outcome {
    let m = memory_object(2)?;
    let (first, second) = (WINDOW, WINDOW + 16 * PAGE);
    map(&m, 0, 2 * PAGE as u64, first, Access::ReadWrite)?;
    map(&m, PAGE as u64, PAGE as u64, second, Access::ReadWrite)?;
    // SAFETY: both pages are init's mappings of the object, read and write.
    let seen = unsafe {
        ((first + PAGE + 8) as *mut u64).write_volatile(0x5EE5_BAC4);
        ((second + 8) as *const u64).read_volatile()
    };
    let info = sys::memory_info(&m);
    unmap(first, 2 * PAGE as u64)?;
    unmap(second, PAGE as u64)?;
    let after = sys::memory_info(&m);
    close(m)?;
    check(seen == 0x5EE5_BAC4, "the second mapping shows other frames")?;
    check(
        info.is_ok_and(|i| i.mappings == 2) && after.is_ok_and(|i| i.mappings == 0),
        "MEMORY did not count the mappings",
    )
}

/// mem_unmap(x0 process with MANAGE, x1 address, x2 length) takes exactly
/// one whole mapping (spec 7.4) and changes x0 alone on an error: an
/// address or a length off whole pages, a length of 0 and a range past the
/// lower half fail with INVALID_ARGS, through a closed handle too; then x0
/// (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without MANAGE); a process that
/// ended fails with BAD_STATE; a part of a mapping, more than it, and a
/// range that starts inside it fail with INVALID_ARGS and unmap nothing.
/// The whole mapping goes with 0 in x0 alone, and a second time fails.
fn mem_unmap_takes_whole_mappings() -> Outcome {
    let m = memory_object(4)?;
    let no_manage = copy(&init::PROCESS, Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    map(&m, 0, 4 * PAGE as u64, WINDOW, Access::ReadWrite)?;
    let result = unmap_cases(m.raw().0, no_manage.raw().0, ended.raw().0, gone);
    close(no_manage)?;
    close(ended)?;
    close(m)?;
    result
}

fn unmap_cases(mem: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemUnmap.number();
    let (own, page, at) = (init::PROCESS.raw().0, PAGE as u64, WINDOW as u64);
    let cases = [
        ([own, at + 8, 4 * page], Error::InvalidArgs),
        ([own, at, 4 * page + 8], Error::InvalidArgs),
        ([own, at, 0], Error::InvalidArgs),
        ([own, LOWER_END - page, 2 * page], Error::InvalidArgs),
        ([gone, at, 0], Error::InvalidArgs),
        ([gone, at, 4 * page], Error::BadHandle),
        ([mem, at, 4 * page], Error::WrongType),
        ([no_manage, at, 4 * page], Error::AccessDenied),
        ([ended, at, 4 * page], Error::BadState),
        ([own, at, page], Error::InvalidArgs),
        ([own, at, 8 * page], Error::InvalidArgs),
        ([own, at + page, 3 * page], Error::InvalidArgs),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    // SAFETY: the page is init's mapping, which the refused calls kept.
    let kept = unsafe { ((WINDOW + 3 * PAGE) as *const u64).read_volatile() } == 0;
    check(
        cases,
        "a bad mem_unmap did not fail alone as spec 11 orders it",
    )?;
    check(kept, "a refused mem_unmap took the mapping")?;
    check(
        x0_alone::<N>(&[own, at, 4 * page], 0),
        "the whole mapping did not go with 0 alone",
    )?;
    check(
        x0_alone::<N>(&[own, at, 4 * page], Error::InvalidArgs.code()),
        "a mapping went twice",
    )
}

/// mem_protect(x0 process with MANAGE, x1 address, x2 length, x3 access)
/// takes exactly one whole mapping within the rights it was mapped with
/// (spec 5.2, 7.4), and changes x0 alone on an error: the range as
/// mem_unmap checks it and an access other than R, RW or RX fail with
/// INVALID_ARGS, through a closed handle too; then x0 (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without MANAGE); a process that ended fails
/// with BAD_STATE; a part of a mapping fails with INVALID_ARGS; RX of a
/// mapping made through a copy without MAP_EXEC fails with ACCESS_DENIED.
/// R and then RW again change the access with 0 alone, and the pages keep
/// their contents.
fn mem_protect_takes_whole_mappings_within_their_rights() -> Outcome {
    let m = memory_object(2)?;
    let read_write = copy(&m, Rights::MAP_READ | Rights::MAP_WRITE)?;
    let no_manage = copy(&init::PROCESS, Rights::NONE)?;
    let ended = ended_child()?;
    let gone = closed_handle()?;
    map(&read_write, 0, 2 * PAGE as u64, WINDOW, Access::ReadWrite)?;
    // SAFETY: the page is init's mapping, read and write.
    unsafe { ((WINDOW + 8) as *mut u64).write_volatile(0x7E57) };
    let result = protect_cases(m.raw().0, no_manage.raw().0, ended.raw().0, gone);
    let unmapped = unmap(WINDOW, 2 * PAGE as u64);
    close(read_write)?;
    close(no_manage)?;
    close(ended)?;
    close(m)?;
    result.and(unmapped)
}

fn protect_cases(mem: u64, no_manage: u64, ended: u64, gone: u64) -> Outcome {
    const N: u16 = Call::MemProtect.number();
    let (own, page, at) = (init::PROCESS.raw().0, PAGE as u64, WINDOW as u64);
    let (r, rw, rx) = (
        Access::Read.raw(),
        Access::ReadWrite.raw(),
        Access::ReadExec.raw(),
    );
    let cases = [
        ([own, at + 8, 2 * page, r], Error::InvalidArgs),
        ([own, at, 0, r], Error::InvalidArgs),
        ([own, at, 2 * page, 6], Error::InvalidArgs),
        ([gone, at, 2 * page, 7], Error::InvalidArgs),
        ([gone, at, 2 * page, r], Error::BadHandle),
        ([mem, at, 2 * page, r], Error::WrongType),
        ([no_manage, at, 2 * page, r], Error::AccessDenied),
        ([ended, at, 2 * page, r], Error::BadState),
        ([own, at, page, r], Error::InvalidArgs),
        ([own, at + page, page, r], Error::InvalidArgs),
        ([own, at, 2 * page, rx], Error::AccessDenied),
    ]
    .into_iter()
    .all(|(args, error)| x0_alone::<N>(&args, error.code()));
    check(
        cases,
        "a bad mem_protect did not fail alone as spec 11 orders it",
    )?;
    check(
        x0_alone::<N>(&[own, at, 2 * page, r], 0),
        "R within the rights failed or changed registers past x0",
    )?;
    // SAFETY: the page is init's mapping, readable in any access.
    let read = unsafe { ((WINDOW + 8) as *const u64).read_volatile() };
    check(
        x0_alone::<N>(&[own, at, 2 * page, rw], 0),
        "RW within the rights failed or changed registers past x0",
    )?;
    // SAFETY: as above, writable again.
    let written = unsafe {
        ((WINDOW + 16) as *mut u64).write_volatile(0x7E58);
        ((WINDOW + 16) as *const u64).read_volatile()
    };
    check(
        read == 0x7E57 && written == 0x7E58,
        "the pages lost their contents or their access",
    )
}

/// A process has 64 mappings at most (spec 7.4): the 65th fails with
/// LIMIT_REACHED alone, and once one went the next one maps. Init has
/// INIT_MAPPINGS of its own.
fn mapping_limit_is_64() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let (own, mem, page) = (init::PROCESS.raw().0, m.raw().0, PAGE as u64);
    let mut made = 0;
    while made <= abi::MAX_MAPPINGS as usize
        && map(&m, 0, page, WINDOW + made * PAGE, Access::Read).is_ok()
    {
        made += 1;
    }
    let next = (WINDOW + made * PAGE) as u64;
    let refused = x0_alone::<N>(
        &[own, mem, 0, page, next, Access::Read.raw()],
        Error::LimitReached.code(),
    );
    let freed = unmap(WINDOW, page).is_ok();
    let again = map(&m, 0, page, WINDOW, Access::Read).is_ok();
    let mut unmapped = true;
    for i in 0..made {
        unmapped &= unmap(WINDOW + i * PAGE, page).is_ok();
    }
    close(m)?;
    check(
        made + INIT_MAPPINGS == abi::MAX_MAPPINGS as usize && refused,
        "the 65th mapping did not fail with LIMIT_REACHED alone",
    )?;
    check(freed && again && unmapped, "no mapping fit once one went")
}

/// A page of a message buffer is no page to map (spec 6.2): mem_map of a
/// range that takes init's buffer or the buffer of a new thread of init
/// fails with INVALID_ARGS alone, and the page next to them maps.
fn buffer_page_cannot_be_mapped_over() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(2)?;
    let t = thread(0, add_mark, 0, LOW, Policy::Fifo)?;
    let (own, mem, page, r) = (
        init::PROCESS.raw().0,
        m.raw().0,
        PAGE as u64,
        Access::Read.raw(),
    );
    let refused = [
        abi::INIT_MSGBUF - page,
        abi::INIT_MSGBUF,
        buffer(0) as u64 - page,
    ]
    .into_iter()
    .all(|at| x0_alone::<N>(&[own, mem, 0, 2 * page, at, r], Error::InvalidArgs.code()));
    let next = buffer(0) + PAGE;
    let mapped = map(&m, 0, page, next, Access::Read).and_then(|()| unmap(next, page));
    close(t)?;
    close(m)?;
    check(
        refused,
        "a range over a message buffer was not refused alone",
    )?;
    mapped
}

/// A page of a message buffer is no mapping (spec 6.2): mem_unmap of
/// init's fails with INVALID_ARGS alone, and the buffer keeps its words.
fn buffer_page_cannot_be_unmapped() -> Outcome {
    const N: u16 = Call::MemUnmap.number();
    let word = (abi::INIT_MSGBUF + 8) as *mut u64;
    // SAFETY: the page is init's message buffer, which nothing else uses
    // now.
    unsafe { word.write_volatile(0xB0FF) };
    let refused = x0_alone::<N>(
        &[init::PROCESS.raw().0, abi::INIT_MSGBUF, PAGE as u64],
        Error::InvalidArgs.code(),
    );
    // SAFETY: as above.
    let kept = unsafe { word.read_volatile() } == 0xB0FF;
    check(
        refused,
        "mem_unmap of the message buffer was not refused alone",
    )?;
    check(kept, "the message buffer lost its words")
}

/// A page of a message buffer is no mapping (spec 6.2): mem_protect of
/// init's to R fails with INVALID_ARGS alone, and the buffer stays
/// writable.
fn buffer_page_cannot_be_protected() -> Outcome {
    const N: u16 = Call::MemProtect.number();
    let args = [
        init::PROCESS.raw().0,
        abi::INIT_MSGBUF,
        PAGE as u64,
        Access::Read.raw(),
    ];
    let refused = x0_alone::<N>(&args, Error::InvalidArgs.code());
    let word = (abi::INIT_MSGBUF + 16) as *mut u64;
    // SAFETY: the page is init's message buffer, which nothing else uses
    // now.
    let written = unsafe {
        word.write_volatile(0xB0FE);
        word.read_volatile()
    };
    check(
        refused,
        "mem_protect of the message buffer was not refused alone",
    )?;
    check(written == 0xB0FE, "the message buffer is not writable")
}

/// Maps BIG bytes of the object whose handle is `m` at WINDOW of init, RW,
/// and unmaps them, again and again, until a probe caught the mapping busy
/// (mark 3) or ROUNDS rounds went; mark 2 names the call it makes, and
/// mark 0 notes 1 once every call passed.
extern "C" fn map_big(m: u64) -> ! {
    const ROUNDS: u32 = 1000;
    let m = Handle::<Memory>::from_raw(abi::Handle(m));
    let mut passed = true;
    for _ in 0..ROUNDS {
        if mark(3) != 0 || !passed {
            break;
        }
        MARKS[2].store(Call::MemMap.number().into(), Relaxed);
        passed &= sys::mem_map(&init::PROCESS, &m, 0, BIG, WINDOW, Access::ReadWrite).is_ok();
        MARKS[2].store(Call::MemUnmap.number().into(), Relaxed);
        // SAFETY: the window is the test's, and nothing else uses it.
        passed &= unsafe { sys::mem_unmap(&init::PROCESS, WINDOW, BIG) }.is_ok();
    }
    MARKS[0].store(passed.into(), Relaxed);
    sys::thread_exit()
}

/// Maps and unmaps BIG bytes of a new object at WINDOW of init in a thread
/// at LEVEL (`map_big`), in portions, while a thread at HIGH,
/// `probe(channel)`, waits on a channel whose timer wakes it every
/// PROBE_PERIOD_NS until it finds the mapping in the middle of the portions
/// of a mem_map (`caught_busy`). Once both ended, nothing is mapped there.
fn during_a_long_map(probe: extern "C" fn(u64) -> !) -> Outcome {
    reset_marks();
    let m = memory_object(BIG / PAGE as u64)?;
    let c = channel(QUIET)?;
    let t = timer_at(&c, HIGH)?;
    PROBE_TIMER.store(t.raw().0, Relaxed);
    let prober = spawn(1, probe, c.raw().0, HIGH, Policy::Fifo)?;
    let mapper = spawn(0, map_big, m.raw().0, LEVEL, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| arm(&t, now + PROBE_PERIOD_NS));
    let ran = armed.and_then(|()| let_run());
    for h in [prober, mapper] {
        close(h)?;
    }
    close(t)?;
    close(c)?;
    close(m)?;
    ran?;
    check(
        mark(0) == 1,
        "a mem_map or a mem_unmap of the window failed",
    )?;
    check(
        mark(3) == 1,
        "no probe came in the middle of a long mem_map",
    )
}

/// Waits on channel `c` for the timer of `during_a_long_map`, again and
/// again, until mem_protect RW of the mapping of `map_big`, which changes
/// nothing, says that a long call works on it (BAD_STATE) while `map_big`
/// makes its mem_map, and marks 3; the timer comes again PROBE_PERIOD_NS
/// later otherwise. False once the channel closed.
fn caught_busy(c: u64) -> bool {
    let c = Handle::<Channel>::from_raw(abi::Handle(c));
    let t = Handle::<Timer>::from_raw(abi::Handle(PROBE_TIMER.load(Relaxed)));
    let map = u64::from(Call::MemMap.number());
    while sys::receive(&c).is_ok() {
        // SAFETY: RW is the access of the mapping; nothing changes.
        let probed = unsafe { sys::mem_protect(&init::PROCESS, WINDOW, BIG, Access::ReadWrite) };
        if probed == Err(Error::BadState) && mark(2) == map {
            MARKS[3].store(1, Relaxed);
            return true;
        }
        let now = sys::clock_now().unwrap_or(0);
        let _ = sys::timer_set(&t, now + PROBE_PERIOD_NS);
    }
    false
}

/// Once a mem_map of `map_big` is busy (`caught_busy` on channel `c`),
/// calls mem_unmap and mem_protect on its mapping: mark 1 notes 1 when both
/// fail with BAD_STATE.
extern "C" fn probe_busy(c: u64) -> ! {
    if caught_busy(c) {
        // SAFETY: the calls must fail and change nothing.
        let (unmapped, protected) = unsafe {
            (
                sys::mem_unmap(&init::PROCESS, WINDOW, BIG),
                sys::mem_protect(&init::PROCESS, WINDOW, BIG, Access::Read),
            )
        };
        let busy = unmapped == Err(Error::BadState) && protected == Err(Error::BadState);
        MARKS[1].store(busy.into(), Relaxed);
    }
    sys::thread_exit()
}

/// A mapping that a long call works on is busy (spec 7.7): mem_unmap and
/// mem_protect of it from a thread that runs in the middle of the portions
/// of its mem_map fail with BAD_STATE; once no call works on a mapping
/// both pass.
fn busy_mapping_is_bad_state() -> Outcome {
    during_a_long_map(probe_busy)?;
    let m = memory_object(1)?;
    let mapped = map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite);
    // SAFETY: the mapping is the test's window, which nothing else uses.
    let protected = unsafe { sys::mem_protect(&init::PROCESS, WINDOW, PAGE as u64, Access::Read) };
    let unmapped = unmap(WINDOW, PAGE as u64);
    close(m)?;
    check(
        mark(1) == 1,
        "a busy mapping did not refuse mem_unmap and mem_protect with BAD_STATE",
    )?;
    check(
        mapped.is_ok() && protected.is_ok() && unmapped.is_ok(),
        "mem_protect or mem_unmap failed once no call worked on the mapping",
    )
}

/// Once a mem_map of `map_big` is busy (`caught_busy` on channel `c`), asks
/// for a thread of init whose buffer is the last page of its mapping,
/// which is not mapped yet: mark 1 notes 1 for INVALID_ARGS. A thread made
/// all the same goes at once, with its buffer.
extern "C" fn probe_buffer(c: u64) -> ! {
    if caught_busy(c) {
        let last = WINDOW + BIG as usize - PAGE;
        // SAFETY: the thread never runs.
        let made = unsafe {
            sys::thread_create(
                &init::PROCESS,
                add_mark,
                STACKS[2].top(),
                3,
                LOW,
                Policy::Fifo,
                last,
            )
        };
        MARKS[1].store((made == Err(Error::InvalidArgs)).into(), Relaxed);
        if let Ok(t) = made {
            let _ = t.close();
        }
    }
    sys::thread_exit()
}

/// Rounds of the calls of `long_calls` at most.
const LONG_ROUNDS: u32 = 16;
/// The long calls of memory objects (spec 7.7) that `long_calls` makes.
const LONG_CALLS: [Call; 4] = [
    Call::MemCreate,
    Call::MemMap,
    Call::MemProtect,
    Call::MemUnmap,
];
/// The free frames before the mem_create of `long_calls`.
static FREE_BEFORE: AtomicU64 = AtomicU64::new(0);

/// The bit of `call` among the calls a probe found in the middle of their
/// portions (mark 3).
fn call_bit(call: Call) -> u64 {
    1 << call.number()
}

/// Free frames now (KERNEL_STATS).
fn free_frames() -> u64 {
    sys::kernel_stats(&init::RESOURCE).map_or(0, |s| s.free_frames)
}

/// Makes mem_create of BIG bytes, mem_map of them RX at WINDOW of init,
/// mem_protect to R and mem_unmap, and closes the object, round after
/// round, until a probe found each of them in the middle of its portions
/// (mark 3) or LONG_ROUNDS rounds went; mark 2 names the call it makes,
/// mark 0 notes 1 once every call passed, and mark 1 notes 1 at the end.
extern "C" fn long_calls(_: u64) -> ! {
    let all = LONG_CALLS.iter().fold(0, |bits, &c| bits | call_bit(c));
    let mut passed = true;
    let now = |call: Call| MARKS[2].store(call.number().into(), Relaxed);
    for _ in 0..LONG_ROUNDS {
        if mark(3) == all || !passed {
            break;
        }
        FREE_BEFORE.store(free_frames(), Relaxed);
        now(Call::MemCreate);
        let Ok(m) = sys::mem_create(BIG) else {
            passed = false;
            break;
        };
        now(Call::MemMap);
        passed &= sys::mem_map(&init::PROCESS, &m, 0, BIG, WINDOW, Access::ReadExec).is_ok();
        // SAFETY: the window is the test's, and nothing else uses it.
        unsafe {
            now(Call::MemProtect);
            passed &= sys::mem_protect(&init::PROCESS, WINDOW, BIG, Access::Read).is_ok();
            now(Call::MemUnmap);
            passed &= sys::mem_unmap(&init::PROCESS, WINDOW, BIG).is_ok();
        }
        MARKS[2].store(0, Relaxed);
        passed &= m.close().is_ok();
    }
    MARKS[0].store(passed.into(), Relaxed);
    MARKS[1].store(1, Relaxed);
    sys::thread_exit()
}

/// Waits on channel `c` for its timer, PROBE_TIMER, again and again until
/// `long_calls` ended (mark 1), and looks whether the call mark 2 names is
/// in the middle of its portions, once for each call until it found it so:
/// for mem_create, the free frames fell since the call began, and by less
/// than the object's pages; for the others, mem_protect of their mapping
/// with the access the mapping has when no call works on it fails with
/// BAD_STATE. It marks the call in mark 3, and the timer comes again
/// PROBE_PERIOD_NS later.
extern "C" fn probe_long_calls(c: u64) -> ! {
    let c = Handle::<Channel>::from_raw(abi::Handle(c));
    let t = Handle::<Timer>::from_raw(abi::Handle(PROBE_TIMER.load(Relaxed)));
    while mark(1) == 0 && sys::receive(&c).is_ok() {
        let call = LONG_CALLS
            .into_iter()
            .find(|&n| u64::from(n.number()) == mark(2) && mark(3) & call_bit(n) == 0);
        let caught = match call {
            Some(Call::MemCreate) => {
                let fell = FREE_BEFORE.load(Relaxed).saturating_sub(free_frames());
                fell > 0 && fell < BIG / PAGE as u64
            }
            Some(n) => {
                let access = if n == Call::MemMap {
                    Access::ReadExec
                } else {
                    Access::Read
                };
                // SAFETY: an idle mapping at the window has this access
                // already, so the call changes nothing.
                let probed = unsafe { sys::mem_protect(&init::PROCESS, WINDOW, BIG, access) };
                probed == Err(Error::BadState)
            }
            None => false,
        };
        if let Some(n) = call.filter(|_| caught) {
            MARKS[3].fetch_or(call_bit(n), Relaxed);
        }
        let now = sys::clock_now().unwrap_or(0);
        let _ = sys::timer_set(&t, now + PROBE_PERIOD_NS);
    }
    sys::thread_exit()
}

/// Spec 15.2 (memory), 7.7: long calls let a timer in. A thread at LEVEL
/// makes mem_create of BIG bytes, mem_map of them RX, whose portions take
/// 8 pages and make the instruction cache coherent for them, mem_protect
/// to R and mem_unmap (`long_calls`), while a thread at HIGH wakes every
/// PROBE_PERIOD_NS at its timer (`probe_long_calls`): it runs in the middle
/// of the portions of each of the four calls, each of which passes.
fn long_calls_let_a_timer_in() -> Outcome {
    reset_marks();
    let c = channel(QUIET)?;
    let t = timer_at(&c, HIGH)?;
    PROBE_TIMER.store(t.raw().0, Relaxed);
    let prober = spawn(1, probe_long_calls, c.raw().0, HIGH, Policy::Fifo)?;
    let caller = spawn(0, long_calls, 0, LEVEL, Policy::Fifo)?;
    let armed = clock_now().and_then(|now| arm(&t, now + PROBE_PERIOD_NS));
    let ran = armed.and_then(|()| let_run());
    for h in [prober, caller] {
        close(h)?;
    }
    close(t)?;
    close(c)?;
    ran?;
    check(mark(0) == 1, "a long call failed")?;
    check(
        mark(3) == LONG_CALLS.iter().fold(0, |bits, &c| bits | call_bit(c)),
        "no timer came in the middle of mem_create, mem_map, mem_protect and mem_unmap",
    )
}

/// A message buffer lands in no mapping (spec 6.2): thread_create with its
/// buffer on a page of a mapping that a long mem_map has not mapped yet
/// fails with INVALID_ARGS, and so does one on a page of a whole mapping.
fn thread_buffer_cannot_land_in_a_mapping() -> Outcome {
    during_a_long_map(probe_buffer)?;
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite)?;
    // SAFETY: the thread is refused, and would never run.
    let made = unsafe {
        sys::thread_create(
            &init::PROCESS,
            add_mark,
            STACKS[2].top(),
            3,
            LOW,
            Policy::Fifo,
            WINDOW,
        )
    };
    let refused = made == Err(Error::InvalidArgs);
    if let Ok(t) = made {
        close(t)?;
    }
    unmap(WINDOW, PAGE as u64)?;
    close(m)?;
    check(
        mark(1) == 1,
        "a buffer went on a page of a mapping not mapped yet",
    )?;
    check(refused, "a buffer went on a page of a mapping")
}

/// A mapping keeps its object (spec 4, 7.4): once the only handle to an
/// object of 4 pages closes, its mapping still shows what init wrote, and
/// a new object of 4 pages takes none of its frames; once the mapping
/// goes, init's used memory, the free frames and the pages of kernel pools
/// are what they were before the object.
fn mapped_object_outlives_its_last_handle() -> Outcome {
    const PAGES: usize = 4;
    warm(WINDOW)?;
    close(memory_object(PAGES as u64)?)?;
    let before = counts()?;
    let m = memory_object(PAGES as u64)?;
    map(&m, 0, (PAGES * PAGE) as u64, WINDOW, Access::ReadWrite)?;
    let word = |i: usize| (WINDOW + i * PAGE + 8) as *mut u64;
    for i in 0..PAGES {
        // SAFETY: the page is init's mapping, read and write.
        unsafe { word(i).write_volatile(0xA11E_0000 + i as u64) };
    }
    close(m)?;
    let other = memory_object(PAGES as u64)?;
    // SAFETY: as above; the mapping holds the object.
    let kept = (0..PAGES).all(|i| unsafe { word(i).read_volatile() } == 0xA11E_0000 + i as u64);
    close(other)?;
    // A mapping that lost its object stays: taking it would free the
    // object twice.
    check(kept, "the mapping lost its object with the last handle")?;
    unmap(WINDOW, (PAGES * PAGE) as u64)?;
    check(
        counts()? == before,
        "the object did not go with its mapping",
    )
}

/// mem_protect to RX makes code init wrote runnable (spec 7.4): a page of
/// an object, RW, gets a function that returns 42; once the page is RX,
/// the function runs and returns 42.
fn protect_to_exec_runs_new_code() -> Outcome {
    let m = memory_object(1)?;
    map(&m, 0, PAGE as u64, WINDOW, Access::ReadWrite)?;
    let code = WINDOW as *mut u32;
    for (i, &insn) in RETURN_42.iter().enumerate() {
        // SAFETY: the page is init's mapping, read and write.
        unsafe { code.add(i).write_volatile(insn) };
    }
    // SAFETY: the page holds code init wrote, and nothing else uses it.
    let protected =
        unsafe { sys::mem_protect(&init::PROCESS, WINDOW, PAGE as u64, Access::ReadExec) };
    let got = protected.map(|()| {
        // SAFETY: the page is RX and holds a function that takes nothing
        // and returns a word.
        let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(WINDOW) };
        f()
    });
    unmap(WINDOW, PAGE as u64)?;
    close(m)?;
    check(got == Ok(42), "the code written into the page did not run")
}

/// Init's own pages are mappings (spec 13.3): mem_map over the page of its
/// code, of its data and of its stack fails with INVALID_ARGS alone.
fn init_segments_are_taken() -> Outcome {
    const N: u16 = Call::MemMap.number();
    let m = memory_object(1)?;
    let page = |at: usize| (at & !(PAGE - 1)) as u64;
    let local = 0u64;
    let taken = [
        page(init_segments_are_taken as *const () as usize),
        page(&raw const MARKS as usize),
        page(&raw const local as usize),
    ]
    .into_iter()
    .all(|at| {
        let args = [
            init::PROCESS.raw().0,
            m.raw().0,
            0,
            PAGE as u64,
            at,
            Access::Read.raw(),
        ];
        x0_alone::<N>(&args, Error::InvalidArgs.code())
    });
    close(m)?;
    check(
        taken,
        "a page of init's code, data or stack was not refused alone",
    )
}

// Children with code (spec 7.9, 13.2, 13.3, 15.2): init loads the child
// program (tests/child), the boot image's file `child`, with rt::loader.
// Each child asks for its start data through its start channel, a copy of
// the channel of its `Kid` with the label START, and the reply names its
// role (child::Role). Init waits for a child's requests and for its end
// on that channel, and a timer bounds each wait (spec 10).

/// Where init maps the boot image for the whole run, the window its loader
/// copies segments through, and where it sees the page of marks it maps
/// into each child at child::MARKS: gigabytes of their own, far from its
/// program, its stack, its buffers and WINDOW.
const IMAGE: usize = 0x50_0000_0000;
const LOADER_WINDOW: usize = 0x60_0000_0000;
const KID_MARKS: usize = 0x70_0000_0000;
/// The size of the boot image and the handle of the page of marks, which
/// `prepare` sets before the tests run.
static IMAGE_SIZE: AtomicU64 = AtomicU64::new(0);
static KID_MARKS_OBJECT: AtomicU64 = AtomicU64::new(0);
/// The label of a child's start channel (process_create x5), and that of
/// the exit channel of a grandchild.
const START: u64 = 0x57A7;
const GRANDCHILD: u64 = 0x6C1D;
/// How long init waits for a child's request or its end.
const KID_WAIT_NS: u64 = 1_000_000_000;
/// The pause of init between two looks at a child that counts.
const PAUSE_NS: u64 = 1_000_000;
/// The quota of a child that owns no object (spec 7.5): the root of its
/// tables, two pages of its pool of blocks (the directory with the first
/// chunk of its table, then the table of its mappings), seven tables (one
/// of level 1; one of level 2 and one of level 3 each for the program, the
/// stack and the message buffer), the page of its pool of threads and its
/// buffer: 12 pages, and 3 more, which a mapping pays ahead for its tables
/// until it ends: the last mapping, of the page of marks, needs them.
const LEAF_QUOTA: u64 = 15 * PAGE as u64;
/// A child that maps child::SCRATCH_PAGES pages of an object of its own:
/// the pages, the node of their list and a page of its pool of memory
/// objects more; the mapping, under the table of its marks, takes no
/// table.
const SCRATCH_QUOTA: u64 = LEAF_QUOTA + (child::SCRATCH_PAGES as u64 + 2) * PAGE as u64;
/// A child with two threads besides its first: their message buffers
/// more, under the table of its first thread's buffer.
const THREADS_QUOTA: u64 = LEAF_QUOTA + 2 * PAGE as u64;
/// A child that runs Role::Ceiling: pages of its pools of channels,
/// sessions and shells more, and a page for its table.
const CEILING_QUOTA: u64 = LEAF_QUOTA + 4 * PAGE as u64;
/// A child that runs Role::Service needs no more than a leaf: it maps the
/// object that comes to it at child::SHARED, under the table of its
/// program, and the 3 pages a mapping pays ahead for are a leaf's.
const SERVICE_QUOTA: u64 = LEAF_QUOTA;
/// A child that runs Role::Provider: its object of child::SHARED_PAGES
/// pages, the node of their list, and a page of its pool of memory
/// objects more; the object at child::SHARED takes no table either.
const PROVIDER_QUOTA: u64 = LEAF_QUOTA + (child::SHARED_PAGES as u64 + 2) * PAGE as u64;
/// A child that loads a child of its own: its 12 pages as a leaf, tables
/// for the boot image and for the loader's window, pages of its pools of
/// memory objects, shells, channels and sessions, the grandchild's
/// objects, under 20 pages, the grandchild's LEAF_QUOTA, and 3 pages paid
/// ahead: an upper bound with room, not measured.
const GRANDPARENT_QUOTA: u64 = 64 * PAGE as u64;
/// What `Kid::load` says when the child's quota fell short.
const KID_NO_MEMORY: &str = "the child's quota fell short of its loading";
/// The parts of a fault's ESR the tests compare (spec 7.9, [G22]): the
/// exception class, bits 31:26 (data abort, instruction abort from EL0);
/// the fault's class, bits 5:2 of the fault status (translation,
/// permission; bits 1:0, the level, depend on the tables the child has);
/// WnR, bit 6.
const DATA_ABORT: u64 = 0x24;
const INSTRUCTION_ABORT: u64 = 0x20;
const WFX: u64 = 0x01;
const TRANSLATION: u64 = 0b0001;
const PERMISSION: u64 = 0b0011;

/// Maps the boot image at IMAGE, read-only, and a new page of marks at
/// KID_MARKS, for the tests of children with code.
fn prepare() -> Outcome {
    let image: Handle<Memory> = Handle::from_raw(INIT_BOOT_IMAGE);
    let size = sys::memory_info(&image)
        .map_err(|_| "MEMORY of the boot image failed")?
        .size;
    map(&image, 0, size, IMAGE, Access::Read)?;
    IMAGE_SIZE.store(size, Relaxed);
    let marks = memory_object(1)?;
    map(&marks, 0, PAGE as u64, KID_MARKS, Access::ReadWrite)?;
    KID_MARKS_OBJECT.store(marks.raw().0, Relaxed);
    Ok(())
}

/// The child program, the boot image's file `child` (tests/child).
fn child_program() -> Result<Program<'static>, &'static str> {
    let size = IMAGE_SIZE.load(Relaxed) as usize;
    // SAFETY: `prepare` mapped the boot image at IMAGE for the whole run,
    // read-only; before it, the slice is empty.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size) };
    bootimg::BootImage::parse(bytes)
        .ok()
        .and_then(|image| image.files().find(|f| f.name == "child"))
        .and_then(|file| Program::parse(file.data).ok())
        .ok_or("the boot image has no child program")
}

/// The addresses of `part` of the child program.
fn part_of(part: Part) -> Result<core::ops::Range<u64>, &'static str> {
    let s = child_program()?.segments[part as usize];
    Ok(s.vaddr..s.vaddr + s.mem_size)
}

/// `counts` once the threads and the cleanup below init ran (`let_run`):
/// the objects of a child that ended go back at the level of its end
/// (spec 7.7).
fn counts_at_rest() -> Result<(u64, u64, u64), &'static str> {
    let_run()?;
    counts()
}

/// Mark `i` of the page children share with init.
fn kid_mark(i: usize) -> u64 {
    // SAFETY: `prepare` mapped the page at KID_MARKS, readable and
    // writable, for the whole run; children write it too, so each word is
    // reached as an atomic.
    unsafe { &*(KID_MARKS as *const AtomicU64).add(i) }.load(Relaxed)
}

fn reset_kid_marks() {
    for i in 0..PAGE / 8 {
        // SAFETY: as in `kid_mark`.
        unsafe { &*(KID_MARKS as *const AtomicU64).add(i) }.store(0, Relaxed);
    }
}

/// Waits `ns` nanoseconds in receive on a timer of a channel of its own,
/// at init's level: threads below init run meanwhile, and the timer fires
/// ahead of them. The boost of its expiry ends with a receive that finds
/// nothing (spec 6.6).
fn sleep(ns: u64) -> Outcome {
    let c = channel(QUIET)?;
    let t = timer_at(&c, TEST_PRIORITY)?;
    let waited = arm(&t, clock_now()? + ns).map(|()| sys::receive(&c));
    let _ = sys::try_receive(&c);
    close(t)?;
    close(c)?;
    check(
        waited == Ok(Ok(expiry(0, 1))),
        "the pause did not end at its timer",
    )
}

/// A handle a child gets in the reply to its start request, a copy with
/// TRANSFER of: its own process with MANAGE and DUPLICATE, its first
/// thread with MANAGE, the system resource with DEBUG, the boot image with
/// MAP_READ, the page of marks with MAP_READ and MAP_WRITE, or the channel
/// of its `Ear` with NOTIFY and the label GRANDCHILD; or a handle of init
/// with TRANSFER, which moves to the child.
#[derive(Clone, Copy)]
enum Gift {
    Own,
    Thread,
    Debug,
    Image,
    Marks,
    GrandchildExit,
    Given(abi::Handle),
}

/// What init hears a child through: a channel that takes the child's
/// start requests (label START), its end (label CHILD) and the expiries of
/// a timer that bounds each wait (label 0), and the copy of the channel
/// that is the child's exit channel.
struct Ear {
    channel: Handle<Channel>,
    exit: Handle<Channel>,
    timer: Handle<Timer>,
}

impl Ear {
    /// A new ear, and the copy of its channel with SEND, NOTIFY, TRANSFER
    /// and the label START that becomes the child's start channel.
    fn new() -> Result<(Ear, Handle<Channel>), &'static str> {
        let channel = channel(QUIET)?;
        let exit = session(&channel, Rights::NOTIFY, CHILD, QUIET)?;
        let timer = timer(&channel)?;
        let rights = Rights::SEND | Rights::NOTIFY | Rights::TRANSFER;
        let start = session(&channel, rights, START, QUIET)?;
        Ok((
            Ear {
                channel,
                exit,
                timer,
            },
            start,
        ))
    }

    /// What the channel takes next, within KID_WAIT_NS: a request or a
    /// notification. The CLIENT_GONE of a copy that went, the start
    /// channel of a child that ended or the exit channel a grandparent
    /// held, does not count, nor does an expiry before the deadline: one of
    /// an earlier wait that came after its answer, since timer_cancel
    /// leaves the bits that were set and a timer never fires early (spec
    /// 10).
    fn next(&self) -> Result<Received, &'static str> {
        let deadline = clock_now()? + KID_WAIT_NS;
        arm(&self.timer, deadline)?;
        let got = loop {
            match sys::receive(&self.channel) {
                Ok(Received::Notification {
                    source: Source::Session,
                    bits: CLIENT_GONE,
                    ..
                }) => continue,
                Ok(Received::Notification {
                    source: Source::Timer,
                    ..
                }) if clock_now().is_ok_and(|now| now < deadline) => continue,
                other => break other,
            }
        };
        let cancelled = sys::timer_cancel(&self.timer);
        match got {
            _ if cancelled.is_err() => Err("timer_cancel failed"),
            Ok(Received::Notification {
                source: Source::Timer,
                ..
            }) => Err("the child neither asked nor ended in time"),
            Ok(got) => Ok(got),
            Err(_) => Err("receive on the child's channel failed"),
        }
    }

    /// What the channel holds now, past the CLIENT_GONE of copies that
    /// went.
    fn now(&self) -> Result<Received, Error> {
        loop {
            match sys::try_receive(&self.channel) {
                Ok(Received::Notification {
                    source: Source::Session,
                    bits: CLIENT_GONE,
                    ..
                }) => continue,
                other => return other,
            }
        }
    }

    /// Waits for the child's start request (spec 13.3), child::HELLO, and
    /// answers it with `role`, `args` and `handles`, which move to the
    /// child.
    fn answer(&self, role: Role, args: &[u64], handles: &[abi::Handle]) -> Outcome {
        let Received::Message {
            label: START,
            len: 8,
            handles: 0,
            token,
            words,
        } = self.next()?
        else {
            return Err("the child did not ask for its start data");
        };
        check(
            words[0] == child::HELLO,
            "the child's start request is not HELLO",
        )?;
        token
            .reply_handles(&child::reply(role, args), handles)
            .map_err(|_| "the reply to the start request failed")
    }

    /// Waits for the child's exit notification (spec 7.9).
    fn ended(&self) -> Outcome {
        check(
            self.next()? == exit_notice(CHILD),
            "the child's exit notification did not come",
        )
    }

    /// Closes the handles; the channel goes before the copy that is the
    /// exit channel, so that the copy goes without CLIENT_GONE.
    fn close(self) -> Outcome {
        let closed = [self.timer.close(), self.channel.close(), self.exit.close()];
        check(
            closed.iter().all(Result::is_ok),
            "a handle of a child's ear did not close",
        )
    }
}

/// A child with code, its first thread, and its `Ear`.
struct Kid {
    process: Handle<Process>,
    thread: Handle<Thread>,
    ear: Ear,
}

impl Kid {
    /// The child program loaded as a child of init (spec 13.2) with
    /// `quota`, room for `limit` handles, ceiling and priority `level`, its
    /// start channel and its exit channel, and the page of marks mapped at
    /// child::MARKS through a copy with MAP_READ and MAP_WRITE
    /// (loader::map_narrowed); its thread does not run yet.
    fn load(quota: u64, limit: u32, level: u8) -> Result<Kid, &'static str> {
        Kid::load_under(quota, limit, level, level)
    }

    /// `load` with ceiling `ceiling` and the thread at `priority`.
    fn load_under(quota: u64, limit: u32, ceiling: u8, priority: u8) -> Result<Kid, &'static str> {
        let short = |e| match e {
            Error::NoMemory => KID_NO_MEMORY,
            _ => "the child program did not load",
        };
        let program = child_program()?;
        let (ear, start) = Ear::new()?;
        let params = loader::Params {
            quota,
            handle_limit: limit,
            ceiling,
            exit: Some((&ear.exit, QUIET)),
            start: Some(start),
            priority,
            policy: Policy::Fifo,
        };
        // SAFETY: only the loader maps and uses LOADER_WINDOW.
        let loaded = unsafe { loader::load(&init::PROCESS, &program, LOADER_WINDOW, params) };
        let child = match loaded {
            Ok(child) => child,
            Err((e, start)) => {
                let (back, closed) = (start.map_or(Ok(()), Handle::close), ear.close());
                check(
                    back.is_ok() && closed.is_ok(),
                    "a handle of a child that did not load did not close",
                )?;
                return Err(short(e));
            }
        };
        let kid = Kid {
            process: child.process,
            thread: child.thread,
            ear,
        };
        let marks = Handle::<Memory>::from_raw(abi::Handle(KID_MARKS_OBJECT.load(Relaxed)));
        let (page, at) = (PAGE as u64, child::MARKS);
        match loader::map_narrowed(&kid.process, &marks, 0, page, at, Access::ReadWrite) {
            Ok(()) => Ok(kid),
            Err(e) => {
                kid.close()?;
                Err(short(e))
            }
        }
    }

    fn start(&self) -> Outcome {
        sys::thread_start(&self.thread).map_err(|_| "thread_start of the child failed")
    }

    /// Waits for the child's start request and answers it with `role`,
    /// `args` and a copy of each of `gifts`.
    fn serve(&self, role: Role, args: &[u64], gifts: &[Gift]) -> Outcome {
        let mut given = [abi::Handle::INVALID; abi::MESSAGE_HANDLES];
        for (h, &g) in given.iter_mut().zip(gifts) {
            *h = self.gift(g)?;
        }
        self.ear.answer(role, args, &given[..gifts.len()])
    }

    fn gift(&self, g: Gift) -> Result<abi::Handle, &'static str> {
        let marks = Handle::<Memory>::from_raw(abi::Handle(KID_MARKS_OBJECT.load(Relaxed)));
        match g {
            Gift::Own => copy_raw(
                &self.process,
                Rights::MANAGE | Rights::DUPLICATE | Rights::TRANSFER,
            ),
            Gift::Thread => copy_raw(&self.thread, Rights::MANAGE | Rights::TRANSFER),
            Gift::Debug => copy_raw(&init::RESOURCE, Rights::DEBUG | Rights::TRANSFER),
            Gift::Image => copy_raw(
                &Handle::<Memory>::from_raw(INIT_BOOT_IMAGE),
                Rights::MAP_READ | Rights::TRANSFER,
            ),
            Gift::Marks => copy_raw(
                &marks,
                Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER,
            ),
            Gift::GrandchildExit => session(
                &self.ear.channel,
                Rights::NOTIFY | Rights::TRANSFER,
                GRANDCHILD,
                QUIET,
            )
            .map(|h| h.raw()),
            Gift::Given(h) => Ok(h),
        }
    }

    /// Waits for the child's end (spec 7.9): its exit notification, then
    /// why it ended.
    fn end(&self) -> Result<ProcessState, &'static str> {
        self.ear.ended()?;
        sys::process_state(&self.process).map_err(|_| "PROCESS_STATE of the child failed")
    }

    /// Ends the child, if it lives, and closes init's handles.
    fn close(self) -> Outcome {
        let closed = [
            sys::process_kill(&self.process),
            self.thread.close(),
            self.process.close(),
        ];
        let ear = self.ear.close();
        check(
            closed.iter().all(Result::is_ok),
            "a handle of the child did not close",
        )?;
        ear
    }
}

/// The quota of a child with `role`.
fn quota_of(role: Role) -> u64 {
    match role {
        Role::WriteProtected | Role::ReadUnmapped => SCRATCH_QUOTA,
        Role::Grandparent => GRANDPARENT_QUOTA,
        Role::LastThread | Role::ExitProcess | Role::KillItself | Role::BufferBack => THREADS_QUOTA,
        Role::Ceiling => CEILING_QUOTA,
        Role::Service => SERVICE_QUOTA,
        Role::Provider => PROVIDER_QUOTA,
        _ => LEAF_QUOTA,
    }
}

/// A child at LEVEL with the quota of `role` that runs `role` with `args`
/// and `gifts`: why it ended. The cleanup of its end, at its level, ran
/// before this returns (`let_run`): the next test finds the cleanup queue
/// empty.
fn ran(role: Role, args: &[u64], gifts: &[Gift]) -> Result<ProcessState, &'static str> {
    ran_under(role, quota_of(role), LEVEL, LEVEL, args, gifts)
}

/// `ran` with `quota`, ceiling `ceiling` and the thread at `priority`.
fn ran_under(
    role: Role,
    quota: u64,
    ceiling: u8,
    priority: u8,
    args: &[u64],
    gifts: &[Gift],
) -> Result<ProcessState, &'static str> {
    let kid = Kid::load_under(quota, 16, ceiling, priority)?;
    let state = kid
        .start()
        .and_then(|()| kid.serve(role, args, gifts))
        .and_then(|()| kid.end());
    kid.close()?;
    let_run()?;
    state
}

/// The fault of a child that ran `role` with `args` and `gifts` (spec
/// 7.9); a child that ended otherwise is a failure.
fn fault_of(role: Role, args: &[u64], gifts: &[Gift]) -> Result<Fault, &'static str> {
    match ran(role, args, gifts)? {
        ProcessState::Fault { esr, far, elr } => Ok(Fault {
            class: esr >> 26 & 0x3F,
            status: esr >> 2 & 0xF,
            write: esr >> 6 & 1,
            far,
            elr,
        }),
        _ => Err("the child did not end with a fault"),
    }
}

/// What the tests of faults compare of a child's reason: the exception
/// class, the fault's class and WnR of its ESR (DATA_ABORT and the other
/// constants above), its FAR and its ELR.
struct Fault {
    class: u64,
    status: u64,
    write: u64,
    far: u64,
    elr: u64,
}

/// A child with code runs and ends (spec 13.2, 13.3, 7.9): the loader puts
/// the child program into a new process, whose thread marks its start,
/// asks for its start data and ends with the code the reply named; the exit
/// notification comes, PROCESS_STATE gives the code, and once init closed
/// its handles, its used memory, the free frames and the pages of kernel
/// pools are what they were. A child that ran first leaves places in
/// init's pools, so that the second takes no page of them.
fn child_with_code_runs_and_exits() -> Outcome {
    const CODE: u64 = 0x5EED_C0DE;
    ran(Role::Exit, &[0], &[])?;
    reset_kid_marks();
    let before = counts_at_rest()?;
    let state = ran(Role::Exit, &[CODE], &[])?;
    let after = counts_at_rest()?;
    check(
        state == ProcessState::Exited { code: CODE },
        "the child did not end with the code of its role",
    )?;
    check(
        kid_mark(child::STARTED) == 1,
        "the child did not mark its start",
    )?;
    check(after == before, "the child left memory taken")
}

/// A child that owns no object loads and runs with LEAF_QUOTA, all it
/// needs (spec 7.5): once loaded it keeps all of it but the 3 pages a
/// mapping pays ahead for, and its thread asks for its start data and
/// ends. With a page less the last mapping, of the page of marks, fails
/// with NO_MEMORY, and init has back what it used.
fn child_loads_in_its_least_quota() -> Outcome {
    let used = || counts_at_rest().map(|c| c.0);
    let before = used();
    let short = Kid::load(LEAF_QUOTA - PAGE as u64, 16, LEVEL);
    let refused = matches!(short, Err(KID_NO_MEMORY));
    if let Ok(kid) = short {
        kid.close()?;
    }
    let back = used();
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let kept = sys::process_memory(&kid.process);
    let state = kid
        .start()
        .and_then(|()| kid.serve(Role::Exit, &[0], &[]))
        .and_then(|()| kid.end());
    kid.close()?;
    check(
        refused,
        "a child with a page less than its least quota loaded",
    )?;
    check(
        before.is_ok() && back == before,
        "the child that did not load kept init's memory",
    )?;
    check(
        kept.is_ok_and(|m| m.used == LEAF_QUOTA - 3 * PAGE as u64),
        "the loaded child does not keep all of its quota but the 3 pages paid ahead",
    )?;
    check(
        state == Ok(ProcessState::Exited { code: 0 }),
        "the child with its least quota did not run",
    )
}

/// Spec 15.2 (messages), 13.3: a child's start request comes through its
/// start channel, a copy of init's channel with a label, SEND, NOTIFY and
/// TRANSFER that process_create moved into the child's entry 0: init takes
/// it with the label, 8 bytes, no handle and a token. The seven words of
/// the reply reach the child whole: it sends them back in a second
/// request, and the reply to that one is its exit code.
fn request_through_the_start_channel() -> Outcome {
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let result = kid.start().and_then(|()| echo_rounds(&kid));
    kid.close()?;
    result
}

fn echo_rounds(kid: &Kid) -> Outcome {
    const WORDS: [u64; child::ARGS] = [0x11, 0x2222, 0x33_3333, 4 << 32, 5 << 40, 6 << 48, 7 << 56];
    const ECHOED: u64 = 0xEC40;
    let Received::Message {
        label,
        len,
        handles,
        token,
        words,
    } = kid.ear.next()?
    else {
        return Err("the child sent no request");
    };
    let hello = label == START
        && (len, handles) == (8, 0)
        && words == [child::HELLO, 0, 0, 0, 0, 0, 0, 0]
        && token.raw() != 0;
    token
        .reply(&child::reply(Role::Echo, &WORDS))
        .map_err(|_| "the reply to the start request failed")?;
    let Received::Message {
        label,
        len,
        token,
        words,
        ..
    } = kid.ear.next()?
    else {
        return Err("the child did not send the words back");
    };
    let back = label == START && len == 8 * child::ARGS && words[..child::ARGS] == WORDS;
    token
        .reply(&ECHOED.to_le_bytes())
        .map_err(|_| "the reply to the second request failed")?;
    let state = kid.end()?;
    check(
        hello,
        "the start request did not come with its label, its 8 bytes and a token",
    )?;
    check(back, "the reply's words did not reach the child whole")?;
    check(
        state == ProcessState::Exited { code: ECHOED },
        "the child did not get the reply to its second request",
    )
}

/// Spec 15.2 (faults), 7.9: a child that loads from address 0x10, which
/// nothing maps, ends with a data abort from EL0, a translation fault of a
/// read; FAR is the address, ELR the load, whose address the child marked
/// (child::FAULT_AT), and the kernel prints the fault.
fn child_bad_address_ends_it_with_the_reason() -> Outcome {
    const BAD: u64 = 0x10;
    reset_kid_marks();
    let f = fault_of(Role::Load, &[BAD], &[])?;
    check(
        (f.class, f.status, f.write) == (DATA_ABORT, TRANSLATION, 0),
        "the fault is not a translation fault of a read from EL0",
    )?;
    check(
        f.far == BAD && f.elr == kid_mark(child::FAULT_AT),
        "FAR is not the address, or ELR is not the load",
    )
}

/// Spec 7.4, 3.3 (W^X): the loader maps a child's code through a copy of
/// the object's handle with MAP_READ and MAP_EXEC alone, so mem_protect of
/// it to RW through the child's own process fails with ACCESS_DENIED; a
/// child that then writes a word of its code ends with a data abort from
/// EL0, a permission fault of a write, at that word.
fn child_cannot_write_its_code() -> Outcome {
    let code = part_of(Part::Code)?;
    let pages = code.start..code.end.next_multiple_of(PAGE as u64);
    let args = [pages.start, pages.end - pages.start];
    let f = fault_of(Role::WriteCode, &args, &[Gift::Own])?;
    check(
        (f.class, f.status, f.write) == (DATA_ABORT, PERMISSION, 1),
        "the fault is not a permission fault of a write from EL0",
    )?;
    check(
        code.contains(&f.far) && code.contains(&f.elr),
        "FAR or ELR is not in the child's code",
    )
}

/// Spec 7.4, 3.3 (W^X): mem_protect of a child's data, its stack and its
/// page of marks to RX through its own process fails with ACCESS_DENIED,
/// since they are mapped through copies with MAP_READ and MAP_WRITE alone;
/// a child that then branches to a word of its data, mapped RW, ends with
/// an instruction abort from EL0, a permission fault, with FAR and ELR at
/// that word.
fn child_cannot_run_its_data() -> Outcome {
    let data = part_of(Part::Data)?;
    let stack = u64::from(child_program()?.stack_size);
    let args = [
        data.start,
        data.end.next_multiple_of(PAGE as u64) - data.start,
        abi::INIT_STACK_TOP - stack,
        stack,
    ];
    let f = fault_of(Role::RunData, &args, &[Gift::Own])?;
    check(
        (f.class, f.status) == (INSTRUCTION_ABORT, PERMISSION),
        "the fault is not a permission fault of an instruction fetch from EL0",
    )?;
    check(
        f.far == f.elr && part_of(Part::Data)?.contains(&f.far),
        "FAR and ELR are not the word in the child's data",
    )
}

/// Spec 13.2, 13.3: the loader leaves the page under a child's stack
/// unmapped: a child that recurses without end ends with a data abort from
/// EL0, a translation fault in that page.
fn child_stack_has_a_guard_page() -> Outcome {
    let f = fault_of(Role::Recurse, &[], &[])?;
    let bottom = abi::INIT_STACK_TOP - u64::from(child_program()?.stack_size);
    check(
        (f.class, f.status) == (DATA_ABORT, TRANSLATION),
        "the fault is not a translation fault of a data access from EL0",
    )?;
    check(
        (bottom - PAGE as u64..bottom).contains(&f.far),
        "the fault is not in the page under the stack",
    )
}

/// Spec 7.4, 7.7: a child maps child::SCRATCH_PAGES pages of its own
/// object RW and writes to the last, so the TLB may hold it writable, then
/// makes the mapping R with mem_protect, whose portions of 32 pages forget
/// each of their pages in the TLB within the call, the last page the
/// second of the second portion: the child's next write there ends it
/// with a data abort from EL0, a permission fault of a write at that page.
fn child_read_only_mapping_refuses_a_write() -> Outcome {
    write_protected(Access::Read)
}

/// Spec 7.4, 7.7, 3.3 (W^X): as `child_read_only_mapping_refuses_a_write`,
/// with the mapping made RX in portions of 8 pages, the last page the
/// second of the fifth: a page that became executable is no longer
/// writable once mem_protect returns.
fn child_executable_mapping_refuses_a_write() -> Outcome {
    write_protected(Access::ReadExec)
}

/// A child that ran Role::WriteProtected with `access` ended with a
/// permission fault of a write from EL0 at child::SCRATCH_LAST.
fn write_protected(access: Access) -> Outcome {
    let f = fault_of(Role::WriteProtected, &[access.raw()], &[Gift::Own])?;
    check(
        (f.class, f.status, f.write) == (DATA_ABORT, PERMISSION, 1),
        "the fault is not a permission fault of a write from EL0",
    )?;
    check(
        f.far == child::SCRATCH_LAST as u64,
        "FAR is not the page whose access changed",
    )
}

/// Spec 7.4, 7.7: a child maps child::SCRATCH_PAGES pages of its own
/// object RW, writes and reads the last, so the TLB may hold it, and
/// unmaps the mapping, whose portions of 32 pages take each of their pages
/// out of its tables and of the TLB, the last page the second of the
/// second portion: its next read there ends it with a data abort from
/// EL0, a translation fault of a read at that page.
fn child_access_after_unmap_faults() -> Outcome {
    let f = fault_of(Role::ReadUnmapped, &[], &[Gift::Own])?;
    check(
        (f.class, f.status, f.write) == (DATA_ABORT, TRANSLATION, 0),
        "the fault is not a translation fault of a read from EL0",
    )?;
    check(
        f.far == child::SCRATCH_LAST as u64,
        "FAR is not the page that went",
    )
}

/// Spec 13.2: a child's panic prints its message through the resource the
/// child got with DEBUG, which xtask finds whole, and ends the child with
/// abi::PANIC_EXIT_CODE.
fn child_panic_exits_with_101() -> Outcome {
    let state = ran(Role::Panic, &[], &[Gift::Debug])?;
    check(
        state
            == ProcessState::Exited {
                code: abi::PANIC_EXIT_CODE,
            },
        "the child's panic did not end it with 101",
    )
}

/// Spec 4, 7.7, 7.9: a child loads a grandchild itself, the child program
/// again, which counts in a mark below both. Once the grandchild counted,
/// init kills the child: the kill ends the grandchild with it, and before
/// process_kill returns the teardown of both ran: the cleanup queue is
/// empty, the exit notifications of both wait in init's channel, the
/// grandchild's through the copy of that channel its parent got, and the
/// count stays where it was. The request the child waited in gets
/// PEER_CLOSED. Once init closed its handles, its used memory, the free
/// frames and the pages of kernel pools are what they were.
fn grandchildren_die_with_their_parent() -> Outcome {
    reset_kid_marks();
    let before = counts_at_rest()?;
    let kid = Kid::load(GRANDPARENT_QUOTA, 16, LEVEL)?;
    let result = kid.start().and_then(|()| generations(&kid));
    kid.close()?;
    result?;
    check(
        counts_at_rest()? == before,
        "the child or the grandchild left memory taken",
    )
}

fn generations(kid: &Kid) -> Outcome {
    const COUNT: usize = 1;
    let args = [LEAF_QUOTA, LOW.into(), COUNT as u64];
    let gifts = [Gift::Own, Gift::Image, Gift::GrandchildExit, Gift::Marks];
    kid.serve(Role::Grandparent, &args, &gifts)?;
    let Received::Message { token, .. } = kid.ear.next()? else {
        return Err("the child did not say that its child runs");
    };
    let mut counted = 0;
    for _ in 0..KID_WAIT_NS / PAUSE_NS {
        sleep(PAUSE_NS)?;
        counted = kid_mark(COUNT);
        if counted > 0 {
            break;
        }
    }
    let killed = sys::process_kill(&kid.process);
    let queue = sys::kernel_stats(&init::RESOURCE).map(|s| s.cleanup_queue);
    let stopped = kid_mark(COUNT);
    let notices = [(); 3].map(|()| kid.ear.now());
    sleep(PAUSE_NS)?;
    let later = kid_mark(COUNT);
    let answered = token.reply(&[]);
    check(counted > 0, "the grandchild did not count")?;
    check(
        killed.is_ok() && queue == Ok(0),
        "process_kill failed, or returned before the teardown",
    )?;
    check(
        notices
            == [
                Ok(exit_notice(GRANDCHILD)),
                Ok(exit_notice(CHILD)),
                Err(Error::WouldBlock),
            ],
        "the exit notifications of the grandchild and the child were not there when process_kill returned",
    )?;
    check(
        later == stopped,
        "the grandchild counted after its parent's end",
    )?;
    check(
        answered == Err(Error::PeerClosed),
        "the reply to the killed child was not PEER_CLOSED",
    )
}

/// Spec 7.5, 7.8: a child with LEAF_QUOTA and room for 1024 handles
/// copies a handle until a call fails, closes the copies and starts over,
/// until it made 1000 copies: the chunks of its table come out of its own
/// quota, so each round ends with NO_MEMORY, the most it used is within
/// its quota, and the pools take at most a page per page of its quota and
/// one more. Once init closed its handles, its used memory, the free
/// frames and the pages of kernel pools are what they were.
fn child_table_churn_stays_under_its_quota() -> Outcome {
    const COPIES: u64 = 1000;
    reset_kid_marks();
    let before = counts_at_rest()?;
    let kid = Kid::load(LEAF_QUOTA, 1024, LEVEL)?;
    let state = kid
        .start()
        .and_then(|()| kid.serve(Role::Churn, &[COPIES], &[Gift::Own]))
        .and_then(|()| kid.end());
    let pools = counts().map(|c| c.2);
    kid.close()?;
    let after = counts_at_rest()?;
    let [made, rounds, full, most, quota] = [
        child::MADE,
        child::ROUNDS,
        child::FULL,
        child::MOST_USED,
        child::QUOTA,
    ]
    .map(kid_mark);
    check(
        state == Ok(ProcessState::Exited { code: 0 }),
        "the child's copies failed",
    )?;
    check(
        made >= COPIES && rounds > 1 && full == rounds,
        "a round of copies did not end with NO_MEMORY",
    )?;
    check(
        quota == LEAF_QUOTA && most <= quota,
        "the child used more than its quota",
    )?;
    check(
        pools.is_ok_and(|p| p.saturating_sub(before.2) <= LEAF_QUOTA / PAGE as u64 + 1),
        "the pools took more pages than the child's quota and one",
    )?;
    check(after == before, "the child left memory taken")
}

/// A child under ceiling child::CEILING, 30, makes the calls of `checked`
/// from EL0 (Role::Ceiling, spec 8, 11) against a thread and its process
/// under ceiling 63 that init made, with no code: a priority above the
/// caller's own ceiling fails with ACCESS_DENIED alone, in its place in
/// the order of the call's checks, and one at the ceiling passes it.
fn caller_ceiling(checked: Checked) -> Outcome {
    let target = child(abi::PRIORITY_LEVELS - 1)?;
    let t = child_thread(&target, LEVEL);
    let state = match &t {
        Ok(t) => copy_raw(t, Rights::MANAGE | Rights::TRANSFER).and_then(|thread| {
            let process = copy_raw(&target, Rights::MANAGE | Rights::TRANSFER)?;
            let gifts = [Gift::Given(thread), Gift::Given(process)];
            let (quota, level) = (quota_of(Role::Ceiling), child::CEILING);
            ran_under(
                Role::Ceiling,
                quota,
                level,
                LEVEL,
                &[checked as u64],
                &gifts,
            )
        }),
        Err(_) => Err("thread_create in the target failed"),
    };
    close(target)?;
    if let Ok(t) = t {
        close(t)?;
    }
    check(
        state? == ProcessState::Exited { code: 0 },
        "a call above the caller's own ceiling did not fail as it must",
    )
}

// The life and the end of processes (spec 4, 6.7, 6.8, 7.7, 7.9, 8):
// children with code end in each way a process ends, and init looks at
// what is left.

/// Spec 7.9, 15.2 (faults): a child that loads from the kernel's image
/// (child::KERNEL), which EL0 may not reach, ends with a data abort from
/// EL0, a permission fault of a read at that address, and the fault ends
/// it alone: a neighbour, another child that waits in receive meanwhile,
/// takes init's request afterwards and answers it. ELR is the load, whose
/// address the child marked (child::FAULT_AT).
fn el0_fault_ends_only_the_process() -> Outcome {
    reset_kid_marks();
    let c = channel(LEVEL)?;
    let send = copy(&c, Rights::SEND)?;
    let neighbour = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let waits = neighbour
        .start()
        .and_then(|()| neighbour.serve(Role::Serve, &[1], &[Gift::Given(c.raw())]))
        .and_then(|()| let_run());
    let fault = waits.and_then(|()| fault_of(Role::Load, &[child::KERNEL], &[]));
    let answer = sys::try_send(&send, &FAULT_WORD.to_le_bytes());
    let state = neighbour.end();
    neighbour.close()?;
    close(send)?;
    let f = fault?;
    check(
        (f.class, f.status, f.write) == (DATA_ABORT, PERMISSION, 0),
        "the fault is not a permission fault of a read from EL0",
    )?;
    check(
        f.far == child::KERNEL && f.elr == kid_mark(child::FAULT_AT),
        "FAR is not the kernel's address, or ELR is not the load",
    )?;
    check(
        answer.is_ok_and(|r| r.len == 8 && r.words[0] == FAULT_WORD)
            && state == Ok(ProcessState::Exited { code: 0 }),
        "the neighbour did not answer after the fault",
    )
}

/// The request init sends to the neighbour of a fault.
const FAULT_WORD: u64 = 0x4E16_4B0E;

/// Spec 7.9: `wfi` at EL0 traps (SCTLR_EL1.nTWI is clear) and is the
/// program's fault: the child ends with EC 0x01 at its `wfi`, whose
/// address it marked (child::FAULT_AT). A child's fault at 0x10 leaves
/// FAR_EL1 set first, and the reason has FAR 0.
fn wfi_at_el0_is_a_fault() -> Outcome {
    fault_of(Role::Load, &[0x10], &[])?;
    reset_kid_marks();
    let f = fault_of(Role::Wfi, &[], &[])?;
    check(f.class == WFX, "the fault is not a trapped WFI")?;
    check(f.far == 0, "a stale FAR went into the reason")?;
    check(f.elr == kid_mark(child::FAULT_AT), "ELR is not the wfi")
}

/// Spec 8, 11: the exit of the last started thread of a process ends the
/// process with code 0. A child starts a helper below itself, makes a
/// third thread it never starts, and ends its own thread; the helper finds
/// the process alive and ends too. The stopped thread does not keep the
/// process: the exit notification comes, and once init closed its
/// handles, its used memory, the free frames and the pages of kernel pools
/// are what they were.
fn last_thread_exit_ends_the_process() -> Outcome {
    reset_kid_marks();
    let before = counts_at_rest()?;
    let state = ran(Role::LastThread, &[(LEVEL - 1).into()], &[Gift::Own])?;
    let after = counts_at_rest()?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the last thread's exit did not end the process with code 0",
    )?;
    check(
        kid_mark(child::HELPER) == 1 && kid_mark(child::SEEN) == 1,
        "the process ended before its last started thread",
    )?;
    check(after == before, "the stopped thread outlived its process")
}

/// Spec 7.9, 11: process_exit ends the process with its code, whatever
/// its other threads do: a helper the child started below itself never
/// runs.
fn process_exit_ends_the_process_with_its_code() -> Outcome {
    const CODE: u64 = 0x5EED_C0DE;
    reset_kid_marks();
    let args = [CODE, (LEVEL - 1).into()];
    let state = ran(Role::ExitProcess, &args, &[Gift::Own])?;
    check(
        state == ProcessState::Exited { code: CODE },
        "the process did not end with its code",
    )?;
    check(
        kid_mark(child::HELPER) == 0,
        "a ready thread of the ended process ran",
    )
}

/// Spec 11: process_kill of the caller's own process does not return: the
/// child ends killed, and a helper it started below itself never runs.
fn process_kills_itself() -> Outcome {
    reset_kid_marks();
    let state = ran(Role::KillItself, &[(LEVEL - 1).into()], &[Gift::Own])?;
    check(
        state == ProcessState::Killed,
        "process_kill of its own process returned",
    )?;
    check(
        kid_mark(child::HELPER) == 0,
        "a ready thread of the ended process ran",
    )
}

/// Spec 6.2, 8: a thread's message buffer goes at its exit, while a handle
/// keeps the thread. A child starts a helper below itself and lowers
/// itself below it; the helper finds its buffer zeroed and writable, and
/// exits. The child then uses what it used before the helper, and
/// thread_set_priority through its handle to the helper fails with
/// BAD_STATE; the process lives on, and the child ends with 0.
fn exited_thread_gives_its_buffer_back() -> Outcome {
    reset_kid_marks();
    let gifts = [Gift::Own, Gift::Thread];
    let state = ran(Role::BufferBack, &[(LEVEL - 1).into()], &gifts)?;
    check(
        kid_mark(child::SEEN) == 1,
        "the helper did not find its buffer zeroed and writable",
    )?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the thread's buffer outlived its exit, or its handle lost the thread",
    )
}

/// Spec 7.7, 7.9: a child that only its started thread holds: init starts
/// the thread and closes its handles to the child and to the thread at
/// once; the child then exits, its last reference goes within its own end,
/// its exit notification comes, and init has its used memory, the free
/// frames and the pages of kernel pools back as they were: the child
/// went, and went once.
fn orphan_exit_frees_the_process() -> Outcome {
    orphan(Role::Exit, &[0])
}

/// As orphan_exit_frees_the_process, with a child that faults at a bad
/// address.
fn orphan_fault_frees_the_process() -> Outcome {
    orphan(Role::Load, &[0x10])
}

fn orphan(role: Role, args: &[u64]) -> Outcome {
    let before = counts_at_rest()?;
    let Kid {
        process,
        thread,
        ear,
    } = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let started = sys::thread_start(&thread);
    let closed = [thread.close(), process.close()];
    let ended = started
        .map_err(|_| "thread_start of the child failed")
        .and_then(|()| ear.answer(role, args, &[]))
        .and_then(|()| ear.ended());
    ear.close()?;
    let after = counts_at_rest()?;
    check(
        closed.iter().all(Result::is_ok),
        "a handle of the child did not close",
    )?;
    ended?;
    check(after == before, "the orphan stayed, or went twice")
}

/// Spec 13.3: a child's start channel, a copy of init's channel with a
/// label and NOTIFY, carries a notification as well: init takes it with
/// the label and the bits.
fn child_notifies_through_its_start_channel() -> Outcome {
    const BITS: u64 = 0b1010;
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let got = kid
        .start()
        .and_then(|()| kid.serve(Role::Notify, &[BITS], &[]))
        .and_then(|()| kid.ear.next());
    let state = kid.end();
    kid.close()?;
    check(
        got == Ok(labelled(START, BITS, 1)),
        "init did not get the child's notification with its label",
    )?;
    check(
        state == Ok(ProcessState::Exited { code: 0 }),
        "notify through the start channel failed",
    )
}

/// A token names a request for the process that took it (spec 6.1): init
/// takes the request of a child and holds it; another child replies with
/// init's token and gets BAD_STATE, and the first child still waits. Then
/// init answers, and the child ends with the reply's first word.
fn reply_from_another_process_is_bad_state() -> Outcome {
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let result = kid.start().and_then(|()| foreign_reply(&kid));
    kid.close()?;
    result
}

fn foreign_reply(kid: &Kid) -> Outcome {
    const ANSWER: u64 = 0xA115;
    kid.serve(Role::Echo, &[ANSWER; child::ARGS], &[])?;
    let Received::Message { token, .. } = kid.ear.next()? else {
        return Err("the child sent no request");
    };
    let other = ran(Role::Reply, &[token.raw(), ANSWER + 1], &[]);
    let waits = kid.ear.now();
    let answered = token.reply(&ANSWER.to_le_bytes());
    let state = kid.end();
    check(
        other
            == Ok(ProcessState::Exited {
                code: Error::BadState.code(),
            }),
        "a child of another process answered init's request",
    )?;
    check(
        waits == Err(Error::WouldBlock) && answered.is_ok(),
        "the child did not wait for init's reply",
    )?;
    check(
        state == Ok(ProcessState::Exited { code: ANSWER }),
        "the child did not get init's reply",
    )
}

/// The boost by a client stops at the ceiling of the service's process
/// (spec 6.6, 8): a child under ceiling 20 serves, at base 10, the request
/// of a thread of init at 30; it works at 20, so a thread of init at 25
/// started right after the request runs before the reply; at 30 the
/// service would answer first.
fn boost_is_capped_by_the_server_ceiling() -> Outcome {
    reset_results();
    let c = channel(LEVEL)?;
    let send = copy(&c, Rights::SEND)?;
    let kid = Kid::load_under(LEAF_QUOTA, 16, 20, LEVEL)?;
    let served = kid
        .start()
        .and_then(|()| kid.serve(Role::Serve, &[1], &[Gift::Given(c.raw())]))
        .and_then(|()| let_run());
    HANDLES[0].store(send.raw().0, Relaxed);
    let raced = served.and_then(|()| {
        let sender = spawn(0, client, 0, HIGH, Policy::Fifo)?;
        let watcher = spawn(1, note_ended, 0, NOTICE, Policy::Fifo)?;
        let_run()?;
        close(sender)?;
        close(watcher)
    });
    let state = kid.end();
    kid.close()?;
    close(send)?;
    raced?;
    check(
        mark(0) == 1,
        "the service answered before the thread at 25 ran, above its ceiling",
    )?;
    check(
        ended(0) && result(0)[0] == 0 && state == Ok(ProcessState::Exited { code: 0 }),
        "the client did not get the service's reply",
    )
}

/// Leaves in mark 0 1 when the client in slot 0 still waits for its
/// reply, 2 when it came back; ends.
extern "C" fn note_ended(_: u64) -> ! {
    MARKS[0].store(1 + u64::from(ended(0)), Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (refusals), 6.8: a child takes the request of a thread of
/// init above it and ends its process without a reply: the stage Replies
/// of its teardown wakes the client with PEER_CLOSED in x0 alone.
fn client_of_a_dead_server_gets_peer_closed() -> Outcome {
    const WORD: u64 = 0xDEAD_5E4F;
    reset_results();
    let c = channel(LEVEL)?;
    let send = copy(&c, Rights::SEND)?;
    let kid = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let waits = kid
        .start()
        .and_then(|()| kid.serve(Role::TakeThenExit, &[], &[Gift::Given(c.raw())]))
        .and_then(|()| let_run());
    let mut x = marked();
    x[..3].copy_from_slice(&[send.raw().0, 8, WORD]);
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    // The client sends at once and waits; the service takes its request
    // and ends once init waits for its end.
    let client = waits.and_then(|()| spawn(0, raw_client, 0, HIGH, Policy::Fifo));
    let state = kid.end();
    kid.close()?;
    close(send)?;
    close(client?)?;
    let after = result(0);
    check(
        ended(0) && after[0] == Error::PeerClosed.code() && after[1..10] == x[1..],
        "the client of the service that ended did not get PEER_CLOSED in x0 alone",
    )?;
    check(
        state == Ok(ProcessState::Exited { code: 0 }),
        "the service did not end with 0",
    )
}

/// A reply to a client that ended while it waited for it is PEER_CLOSED,
/// twice, and still ends the boost by that client (spec 6.6, 6.8): init
/// takes the request of a child at 30 and works at 30; it kills the child,
/// and its reply is PEER_CLOSED, a second one with the same token too,
/// since the reply leaves the mark of the dead client. A thread of init at
/// 25 started right after runs at once: init is back at its own level.
fn reply_to_a_dead_client_is_peer_closed() -> Outcome {
    reset_marks();
    let kid = Kid::load(LEAF_QUOTA, 16, HIGH)?;
    let result = kid.start().and_then(|()| dead_client(&kid));
    kid.close()?;
    result
}

fn dead_client(kid: &Kid) -> Outcome {
    kid.serve(Role::Echo, &[1; child::ARGS], &[])?;
    let Received::Message { token, .. } = kid.ear.next()? else {
        return Err("the child sent no request");
    };
    let raw = token.raw();
    let killed = sys::process_kill(&kid.process);
    let first = token.reply(&[]);
    let mut x = marked();
    x[..2].copy_from_slice(&[raw, 0]);
    let second = raw_reply(x)[0];
    let t = spawn(0, add_mark, 0, NOTICE, Policy::Fifo)?;
    let at_once = mark(0);
    let_run()?;
    close(t)?;
    let state = kid.end();
    check(
        killed.is_ok() && first == Err(Error::PeerClosed) && second == Error::PeerClosed.code(),
        "a reply to the client that ended was not PEER_CLOSED, twice",
    )?;
    check(
        at_once == 1,
        "the reply to the client that ended did not end its boost",
    )?;
    check(
        state == Ok(ProcessState::Killed),
        "the client did not end as killed",
    )
}

/// A cycle of requests ends only with a kill (spec 6.7): two children send
/// to each other's channel and wait, neither receiving; init kills the
/// first, whose table held the only handle with RECEIVE of its channel:
/// the channel closes, and the second child's request comes back with
/// PEER_CLOSED, which the child ends with.
fn a_call_cycle_ends_with_the_kill() -> Outcome {
    const WORD: u64 = 0xC1C1E;
    let (to_first, to_second) = (channel(LEVEL)?, channel(LEVEL)?);
    let first = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let second = Kid::load(LEAF_QUOTA, 16, LEVEL)?;
    let sent = [
        (&first, &to_second, &to_first),
        (&second, &to_first, &to_second),
    ]
    .map(|(kid, to, own)| {
        let send = copy_raw(to, Rights::SEND | Rights::TRANSFER)?;
        let keep = copy_raw(own, Rights::RECEIVE | Rights::TRANSFER)?;
        kid.start()?;
        kid.serve(Role::Send, &[WORD], &[Gift::Given(send), Gift::Given(keep)])
    });
    // The children's copies with RECEIVE are the channels' only ones.
    close(to_first)?;
    close(to_second)?;
    let waiting = sent.iter().all(Result::is_ok) && let_run().is_ok();
    let killed = sys::process_kill(&first.process);
    let states = [first.end(), second.end()];
    first.close()?;
    second.close()?;
    check(
        waiting && killed.is_ok(),
        "the children did not both wait in send, or process_kill failed",
    )?;
    check(
        states
            == [
                Ok(ProcessState::Killed),
                Ok(ProcessState::Exited {
                    code: Error::PeerClosed.code(),
                }),
            ],
        "the child whose peer was killed did not get PEER_CLOSED",
    )
}

// Requests and replies (spec 6.1, 6.6): init and threads of its own
// process are clients and services of one another.

/// The label of a client's copy of a channel.
const CLIENT_LABEL: u64 = 0xC11E;

/// Per slot: the handle the thread there uses (`client`, `server`), and
/// what it got (`result`).
static HANDLES: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static RESULTS: [[AtomicU64; 12]; SLOTS] = [const { [const { AtomicU64::new(0) }; 12] }; SLOTS];
/// Per slot: the thread there came back from its call.
static ENDED: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// x0-x9 of the send of `raw_client`.
static RAW: [AtomicU64; 10] = [const { AtomicU64::new(0) }; 10];
/// Mark 1 when `server` took its request.
static SEEN: AtomicU64 = AtomicU64::new(0);

fn reset_results() {
    reset_marks();
    SEEN.store(0, Relaxed);
    for word in RESULTS
        .iter()
        .flatten()
        .chain(&HANDLES)
        .chain(&ENDED)
        .chain(&RAW)
    {
        word.store(0, Relaxed);
    }
}

/// What the thread in `slot` got: the error code of its call or 0, then
/// as `send` or `receive` leave a message: the length, the words of bytes
/// 0-63, the label and the token.
fn result(slot: usize) -> [u64; 12] {
    core::array::from_fn(|i| RESULTS[slot][i].load(Relaxed))
}

fn record(slot: usize, words: &[u64]) {
    for (r, &w) in RESULTS[slot].iter().zip(words) {
        r.store(w, Relaxed);
    }
}

/// Whether the thread in `slot` came back from its call.
fn ended(slot: usize) -> bool {
    ENDED[slot].load(Relaxed) == 1
}

/// The channel handle that HANDLES holds for `slot`.
fn handle(slot: usize) -> Handle<Channel> {
    Handle::from_raw(abi::Handle(HANDLES[slot].load(Relaxed)))
}

/// The 16 bytes the client in `slot` sends.
fn request(slot: usize) -> [u8; 16] {
    core::array::from_fn(|i| (16 * slot + i + 1) as u8)
}

/// `bytes` as x2-x9 carry them.
fn words(bytes: &[u8]) -> [u64; 8] {
    abi::inline_words(bytes)
}

/// send with raw registers.
fn raw_send(x: Regs) -> Regs {
    // SAFETY: send only reads its registers; the calls that come here fail
    // or are answered by threads of the test.
    unsafe { sys::raw::<{ Call::Send.number() }>(x) }
}

/// reply with raw registers.
fn raw_reply(x: Regs) -> Regs {
    // SAFETY: reply only reads its registers and never waits.
    unsafe { sys::raw::<{ Call::Reply.number() }>(x) }
}

/// The token of the request queued in `c`, taken without waiting.
fn take_token(c: &Handle<Channel>) -> Result<Token, &'static str> {
    match sys::try_receive(c) {
        Ok(Received::Message { token, .. }) => Ok(token),
        _ => Err("no request came"),
    }
}

/// A client of a test in `slot`: sends request(slot) through the handle
/// HANDLES holds for it and waits for the reply, which `result` gives,
/// with 0 for the code; then ends.
extern "C" fn client(slot: u64) -> ! {
    let s = slot as usize;
    match sys::send(&handle(s), &request(s)) {
        Ok(reply) => {
            let mut w = [0; 10];
            w[1] = reply.len as u64;
            w[2..].copy_from_slice(&reply.words);
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// A client that sends with the registers RAW holds and leaves x0-x9 of
/// the call in `result`; then ends.
extern "C" fn raw_client(slot: u64) -> ! {
    let s = slot as usize;
    let after = raw_send(core::array::from_fn(|i| RAW[i].load(Relaxed)));
    record(s, &after);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// A service in `slot`: takes a request on the channel HANDLES holds for
/// it and leaves its length, words, label and token in `result`, and mark
/// 1 at that moment in SEEN; answers with the request's own bytes and
/// leaves the reply's code in `result`; sets mark 2 and ends.
extern "C" fn server(slot: u64) -> ! {
    let s = slot as usize;
    match sys::receive(&handle(s)) {
        Ok(Received::Message {
            label,
            len,
            token,
            words,
            ..
        }) => {
            let mut w = [0; 12];
            w[1] = len as u64;
            w[2..10].copy_from_slice(&words);
            w[10] = label;
            w[11] = token.raw();
            record(s, &w);
            SEEN.store(mark(1), Relaxed);
            let bytes = abi::inline_bytes(&words);
            let replied = token.reply(&bytes[..len.min(abi::INLINE_MAX)]);
            RESULTS[s][0].store(replied.map_or_else(|e| e.code(), |()| 0), Relaxed);
        }
        Ok(_) => record(s, &[u64::MAX]),
        Err(e) => record(s, &[e.code()]),
    }
    MARKS[2].store(1, Relaxed);
    sys::thread_exit()
}

/// send and reply check their values first (spec 6.1, 11): a length above
/// 1024, more than 4 handles, a bit no description has, and NO_WAIT for
/// reply fail with INVALID_ARGS before the handle or the token is looked
/// at; then the handle of send: BAD_HANDLE, WRONG_TYPE for a process,
/// ACCESS_DENIED for a copy without SEND, and PEER_CLOSED once the channel
/// closed. Each changes x0 alone. rt refuses more than 1024 bytes
/// itself.
fn send_checks_its_arguments() -> Outcome {
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let shut = channel(QUIET)?;
    let left = copy(&shut, Rights::SEND)?;
    let gone = shut.raw();
    close(shut)?;
    let cases = [
        (c.raw(), 1025, Error::InvalidArgs),
        (c.raw(), 5 << abi::HANDLES_SHIFT, Error::InvalidArgs),
        (c.raw(), 1 << 11, Error::InvalidArgs),
        (c.raw(), 1 << 24, Error::InvalidArgs),
        (c.raw(), 1 << 63, Error::InvalidArgs),
        (gone, 1025, Error::InvalidArgs),
        (gone, 8, Error::BadHandle),
        (init::PROCESS.raw(), 8, Error::WrongType),
        (notify_only.raw(), 8, Error::AccessDenied),
        (left.raw(), 8, Error::PeerClosed),
    ];
    let sent = cases.map(|(h, desc, error)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.0, desc]);
        failed(raw_send(x), x, error)
    });
    let replied =
        [(0, abi::NO_WAIT), (1 << 16, abi::NO_WAIT | 8), (0, 1025)].map(|(token, desc)| {
            let mut x = marked();
            x[..2].copy_from_slice(&[token, desc]);
            failed(raw_reply(x), x, Error::InvalidArgs)
        });
    let typed = sys::send(&c, &[0; abi::MESSAGE_MAX + 1]);
    close(notify_only)?;
    close(left)?;
    close(c)?;
    check(
        sent.iter().all(|&ok| ok),
        "send took a bad description or handle, or changed more than x0",
    )?;
    check(
        replied.iter().all(|&ok| ok),
        "reply took a bad description or looked at the token first",
    )?;
    check(
        typed == Err(Error::InvalidArgs),
        "rt sent more than 1024 bytes",
    )
}

/// Spec 15.2 (messages): a request carries its bytes 0-63 in x2-x9 and
/// comes with the label of the handle it went through (spec 5.3, 6.1). A
/// client above init sends 16 bytes through a copy with a label, and then
/// another through the channel's own handle; init takes each request
/// without waiting: its bytes, no handles, a token that is not 0, and the
/// label, or 0. Init's reply lets each client go.
fn request_carries_registers_and_label() -> Outcome {
    let c = channel(QUIET)?;
    let labelled = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    let result = [(&labelled, CLIENT_LABEL), (&c, 0)]
        .into_iter()
        .try_for_each(|(h, label)| {
            reset_results();
            HANDLES[0].store(h.raw().0, Relaxed);
            let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
            let taken = match sys::try_receive(&c) {
                Ok(Received::Message {
                    label: l,
                    len,
                    handles,
                    token,
                    words: w,
                }) => {
                    let whole = (l, len, handles, w) == (label, 16, 0, words(&request(0)));
                    let named = token.raw() != 0;
                    token.reply(&[]).is_ok() && whole && named
                }
                _ => false,
            };
            close(t)?;
            check(
                taken,
                "the request did not come with its bytes, its label and a token",
            )?;
            check(
                ended(0) && result(0)[..2] == [0, 0],
                "the client did not get the reply",
            )
        });
    close(labelled)?;
    close(c)?;
    result
}

/// Bytes past the length come as zeros (spec 6.1): a client sends 13 bytes
/// through raw registers with every bit of x2-x9 set; init takes x2 whole,
/// the low 5 bytes of x3 and zeros in x4-x9.
fn bytes_past_the_length_come_as_zero() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let x: Regs = core::array::from_fn(|i| match i {
        0 => c.raw().0,
        1 => 13,
        _ => u64::MAX,
    });
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, HIGH, Policy::Fifo)?;
    let (seen, replied) = match sys::try_receive(&c) {
        Ok(Received::Message {
            len, words, token, ..
        }) => (Some((len, words)), token.reply(&[]).is_ok()),
        _ => (None, false),
    };
    close(t)?;
    close(c)?;
    let mut want = [0; 8];
    want[0] = u64::MAX;
    want[1] = (1 << 40) - 1;
    check(
        seen == Some((13, want)),
        "the bytes past the length did not come as zeros",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// Spec 15.2 (messages): the reply comes back in x0-x9 of send (spec 6.1,
/// 11): 0, its description and its bytes. Init answers a client with 13
/// bytes through raw registers, every bit of x2-x9 set: the client gets x2
/// whole, 5 bytes of x3 and zeros, and init's reply changes its x0 alone.
/// A second client gets 64 bytes whole.
fn reply_carries_registers_back() -> Outcome {
    let c = channel(QUIET)?;
    let result = reply_rounds(&c);
    close(c)?;
    result
}

fn reply_rounds(c: &Handle<Channel>) -> Outcome {
    reset_results();
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let mut x = [u64::MAX; 10];
    x[0] = take_token(c)?.raw();
    x[1] = 13;
    let after = raw_reply(x);
    close(t)?;
    let mut want = [0; 10];
    want[1] = 13;
    want[2] = u64::MAX;
    want[3] = (1 << 40) - 1;
    check(
        after[0] == 0 && after[1..] == x[1..],
        "reply failed or changed more than x0",
    )?;
    check(
        ended(0) && result(0)[..10] == want,
        "the reply did not come with zeros past its length",
    )?;
    HANDLES[1].store(c.raw().0, Relaxed);
    let t = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let bytes: [u8; 64] = core::array::from_fn(|i| 0xC0 ^ i as u8);
    let replied = take_token(c)?.reply(&bytes);
    close(t)?;
    let mut want = [0; 10];
    want[1] = 64;
    want[2..].copy_from_slice(&words(&bytes));
    check(
        replied.is_ok() && ended(1) && result(1)[..10] == want,
        "the 64 bytes of a reply did not come whole",
    )
}

/// A client that sends twice through the channel HANDLES holds for
/// `slot`, the second time once the first reply came; `result` gives the
/// second reply. Ends then.
extern "C" fn client_twice(slot: u64) -> ! {
    let s = slot as usize;
    let first = sys::send(&handle(s), &request(s));
    let second = sys::send(&handle(s), &request(s));
    record(s, &[first.and(second).map_or_else(|e| e.code(), |_| 0)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a token answers once (spec 6.1). Init answers a
/// client, which sends again at once; while init holds the second request,
/// the first token, the count after the second and count 0 fail with
/// BAD_STATE, change x0 alone and leave the client waiting; the second
/// token answers it.
fn second_reply_is_bad_state() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client_twice, 0, HIGH, Policy::Fifo)?;
    let result = second_rounds(&c);
    close(t)?;
    close(c)?;
    result
}

fn second_rounds(c: &Handle<Channel>) -> Outcome {
    let first = take_token(c)?;
    let stale = first.raw();
    let replied = first.reply(&[]);
    let second = take_token(c)?;
    let raw = second.raw();
    let again = [stale, raw + (1 << 16), raw & 0xFFFF].map(|v| {
        let mut x = marked();
        x[..2].copy_from_slice(&[v, 0]);
        failed(raw_reply(x), x, Error::BadState)
    });
    let waited = !ended(0);
    let last = second.reply(&[]);
    check(
        replied.is_ok() && last.is_ok() && ended(0) && result(0)[0] == 0,
        "a reply did not reach the client",
    )?;
    check(
        again.iter().all(|&ok| ok) && waited,
        "an old, guessed or zero token was taken, or the call changed more than x0",
    )
}

/// Spec 15.2 (refusals): send with NO_WAIT fails with WOULD_BLOCK when no
/// thread waits in receive (spec 6.1), changes x0 alone and queues
/// nothing. A thread above init makes the call, so init finds its result
/// when spawn returns; a request it left would get a reply, so that the
/// thread never stays waiting.
fn send_without_waiting_is_would_block() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[c.raw().0, abi::NO_WAIT | 8]);
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, HIGH, Policy::Fifo)?;
    let (came_back, after) = (ended(0), result(0));
    let left = match sys::try_receive(&c) {
        Ok(Received::Message { token, .. }) => {
            let _ = token.reply(&[]);
            true
        }
        got => got != Err(Error::WouldBlock),
    };
    close(c)?;
    let_run()?;
    close(t)?;
    check(
        came_back && after[0] == Error::WouldBlock.code() && after[1..10] == x[1..],
        "send with NO_WAIT and no receiver did not fail with WOULD_BLOCK alone",
    )?;
    check(!left, "a send that failed left a request")
}

/// With NO_WAIT, send to a service that waits in receive goes through
/// (spec 6.1): the service takes the request at once, and init waits for
/// the reply all the same: its own bytes back.
fn send_without_waiting_to_a_waiting_server_gets_the_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let bytes = request(3);
    let got = sys::try_send(&c, &bytes);
    let_run()?;
    close(s)?;
    close(c)?;
    check(
        got == Ok(Reply {
            len: 16,
            handles: 0,
            words: words(&bytes),
        }),
        "send with NO_WAIT to a waiting service did not get the reply",
    )?;
    check(
        mark(2) == 1 && result(0)[0] == 0,
        "the service's reply failed",
    )
}

/// Spec 15.2 (priorities): requests wait by the priorities of their
/// clients, within a level in the order they came (spec 6.3). Clients at
/// 10, 30 and 20 send in that order, through copies labelled with their
/// priorities, before init receives; init takes them as 30, 20, 10.
fn requests_come_by_priority() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let levels = [LEVEL, HIGH, TEST_PRIORITY];
    let mut copies = [const { None }; 3];
    for (i, &level) in levels.iter().enumerate() {
        let h = session(&c, Rights::SEND, level.into(), QUIET)?;
        HANDLES[i].store(h.raw().0, Relaxed);
        copies[i] = Some(h);
    }
    let mut threads = [const { None }; 3];
    for (i, &level) in levels.iter().enumerate() {
        threads[i] = Some(spawn(i, client, i as u64, level, Policy::Fifo)?);
        // Each sends before the next: the client at 30 at once, the others
        // once init lets them.
        let_run()?;
    }
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let labels = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in threads.into_iter().flatten() {
        close(h)?;
    }
    for h in copies.into_iter().flatten() {
        close(h)?;
    }
    close(c)?;
    check(
        labels == [30, 20, 10],
        "the requests did not come by the priorities of their clients",
    )?;
    check(
        replied && (0..3).all(ended),
        "a client did not get its reply",
    )
}

/// Answers each request among `got` with no bytes; true when every reply
/// went.
fn answer_all<const N: usize>(got: [Result<Received, Error>; N]) -> bool {
    got.into_iter().all(|g| match g {
        Ok(Received::Message { token, .. }) => token.reply(&[]).is_ok(),
        _ => true,
    })
}

/// Requests and notifications wait in one order by level (spec 6.3):
/// clients at 30 and 10 send, and init notifies the channel, whose slot of
/// label 0 has priority 25: receive gives the request at 30, the
/// notification, then the request at 10.
fn requests_and_notifications_share_one_order() -> Outcome {
    reset_results();
    let c = channel(NOTICE)?;
    let high = session(&c, Rights::SEND, HIGH.into(), QUIET)?;
    let low = session(&c, Rights::SEND, LEVEL.into(), QUIET)?;
    HANDLES[0].store(high.raw().0, Relaxed);
    HANDLES[1].store(low.raw().0, Relaxed);
    let a = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let b = spawn(1, client, 1, LEVEL, Policy::Fifo)?;
    let_run()?;
    let posted = sys::notify(&c, 1);
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let order = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        Ok(Received::Notification {
            source: Source::Unlabeled,
            ..
        }) => NOTICE.into(),
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in [a, b] {
        close(h)?;
    }
    for h in [high, low, c] {
        close(h)?;
    }
    check(
        posted.is_ok() && order == [30, 25, 10],
        "the requests and the notification did not come in one order by level",
    )?;
    check(
        replied && ended(0) && ended(1),
        "a client did not get its reply",
    )
}

/// Spec 15.2 (priorities): a service below its client works at the
/// client's priority from the request on (spec 6.6). A service at 10
/// waits, a thread at init's level 20 is ready behind init, and a client
/// at 30 sends: the service answers before the thread at 20 runs, which it
/// sees in that thread's mark, and the client has its reply by the time
/// init runs again.
fn server_below_its_client_runs_at_the_client() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[2].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let peer = spawn(1, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let k = spawn(2, client, 2, HIGH, Policy::Fifo)?;
    let answered = ended(2);
    let_run()?;
    for h in [k, peer, s] {
        close(h)?;
    }
    close(c)?;
    check(
        answered && SEEN.load(Relaxed) == 0,
        "the service did not answer at its client's priority before the thread at 20 ran",
    )?;
    check(
        mark(1) == 1 && mark(2) == 1,
        "the thread at 20 or the service did not end",
    )
}

/// The boost by a client ends with the reply to it (spec 6.6): a service
/// at 10 takes the request of a client at 30 and answers it, and it drops
/// to 10 at once: init at 20 runs before the service goes on past its
/// reply.
fn boost_ends_with_its_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, server, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let k = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let (answered, went_on) = (ended(1), mark(2));
    let_run()?;
    for h in [k, s] {
        close(h)?;
    }
    close(c)?;
    check(answered, "the client did not get the reply")?;
    check(
        went_on == 0,
        "the service went on past its reply at its client's priority",
    )?;
    check(mark(2) == 1, "the service did not end")
}

/// A service that takes two requests on the channel HANDLES holds for
/// `slot`, the second while it holds the first; it answers the first and
/// sets mark 2, answers the second and sets mark 3, and ends.
extern "C" fn serve_two(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let (
        Ok(Received::Message { token: first, .. }),
        Ok(Received::Message { token: second, .. }),
    ) = (sys::receive(&c), sys::receive(&c))
    {
        let _ = first.reply(&[]);
        MARKS[2].store(1, Relaxed);
        let _ = second.reply(&[]);
        MARKS[3].store(1, Relaxed);
    }
    sys::thread_exit()
}

/// A reply with another token keeps the boost (spec 6.6): a service at 10
/// takes the request of a client at 25, then in its next receive that of
/// a client at 30, which boosts it to 30. It answers the first and goes on
/// at 30: its mark is there before init at 20 runs. It answers the second
/// and drops to 10: init runs before it goes on.
fn other_reply_keeps_the_boost() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    for h in &HANDLES[..3] {
        h.store(c.raw().0, Relaxed);
    }
    let s = spawn(0, serve_two, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let first = spawn(1, client, 1, NOTICE, Policy::Fifo)?;
    let second = spawn(2, client, 2, HIGH, Policy::Fifo)?;
    let (kept, dropped, answered) = (mark(2), mark(3), ended(1) && ended(2));
    let_run()?;
    for h in [first, second, s] {
        close(h)?;
    }
    close(c)?;
    check(answered, "a client did not get its reply")?;
    check(kept == 1, "a reply with another token ended the boost")?;
    check(
        dropped == 0,
        "the reply with the boost's own token did not end it",
    )
}

/// A service that takes a request on the channel HANDLES holds for
/// `slot`, asks it again without waiting, sets mark 2, and mark 3 when
/// that found nothing; then answers and ends.
extern "C" fn serve_after_empty_receive(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let again = sys::try_receive(&c);
        MARKS[2].store(1, Relaxed);
        MARKS[3].store(u64::from(again == Err(Error::WouldBlock)), Relaxed);
        let _ = token.reply(&[]);
    }
    sys::thread_exit()
}

/// The next receive ends the boost by a client (spec 6.6): a service at 10
/// takes the request of a client at 30 and asks the channel again without
/// waiting: WOULD_BLOCK, and it drops to 10, so init at 20 runs before it
/// goes on; its reply from 10 still reaches the client.
fn receive_ends_a_request_boost() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, serve_after_empty_receive, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let k = spawn(1, client, 1, HIGH, Policy::Fifo)?;
    let went_on = mark(2);
    let_run()?;
    for h in [k, s] {
        close(h)?;
    }
    close(c)?;
    check(
        went_on == 0,
        "the service went on at its client's priority past its next receive",
    )?;
    check(
        mark(3) == 1 && ended(1) && result(1)[0] == 0,
        "the second receive found something, or the client did not get the reply",
    )
}

/// The service of `high_client_waits_for_one_started_request`: takes a
/// request on the channel HANDLES holds for slot 0 and holds it until the
/// channel of slot 3 gets a notification, as for work of its own; answers
/// it, and takes the next request at once. SEEN gets mark 1 at the first
/// reply, mark 0 mark 1 at the second take. It answers that request too,
/// sets mark 3 and ends.
extern "C" fn worker(_: u64) -> ! {
    let c = handle(0);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let _ = sys::receive(&handle(3));
        SEEN.store(mark(1), Relaxed);
        let _ = token.reply(&[]);
        if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
            MARKS[0].store(mark(1), Relaxed);
            let _ = token.reply(&[]);
        }
    }
    MARKS[3].store(1, Relaxed);
    sys::thread_exit()
}

/// The spinning thread of `high_client_waits_for_one_started_request`:
/// counts in mark 1, notifies the channel HANDLES holds for slot 3 once,
/// and counts on until mark 3 is set; then ends.
extern "C" fn spin(_: u64) -> ! {
    MARKS[1].fetch_add(1, Relaxed);
    let _ = sys::notify(&handle(3), 1);
    while mark(3) == 0 {
        MARKS[1].fetch_add(1, Relaxed);
    }
    sys::thread_exit()
}

/// Spec 15.2 (priorities): a client above others waits for at most one
/// request its service began (spec 6.6). A service at 30 takes the request
/// of a client at 10 and holds it; a client at 25 sends meanwhile, and a
/// thread at 20 counts and then lets the service go on. The service
/// answers the first request and takes the second at once: the counting
/// thread did not run in between, and both clients get their replies.
fn high_client_waits_for_one_started_request() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let work = channel(QUIET)?;
    for (h, v) in HANDLES.iter().zip([&c, &c, &c, &work]) {
        h.store(v.raw().0, Relaxed);
    }
    let s = spawn(0, worker, 0, HIGH, Policy::Fifo)?;
    let first = spawn(1, client, 1, LEVEL, Policy::Fifo)?;
    let_run()?;
    let counting = spawn(3, spin, 3, TEST_PRIORITY, Policy::Fifo)?;
    let second = spawn(2, client, 2, NOTICE, Policy::Fifo)?;
    let_run()?;
    for h in [s, first, counting, second] {
        close(h)?;
    }
    close(work)?;
    close(c)?;
    let (at_reply, at_take) = (SEEN.load(Relaxed), mark(0));
    check(ended(1) && ended(2), "a client did not get its reply")?;
    check(
        at_reply > 0 && at_take == at_reply,
        "the thread at 20 ran between the reply and the next request",
    )
}

// The departure of a side (spec 5.3, 6.8, 7.7): a closed channel refuses
// requests and wakes those that wait; a request a service took outlives
// the close; CLIENT_GONE comes after the requests of its label; a thread
// gives its number back as it ends.

/// Spec 15.2 (refusals): send through any handle of a channel whose last
/// handle with RECEIVE went fails with PEER_CLOSED (spec 6.8), with
/// NO_WAIT too, and changes x0 alone.
fn send_to_a_closed_channel_is_peer_closed() -> Outcome {
    let c = channel(QUIET)?;
    let plain = copy(&c, Rights::SEND)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    close(c)?;
    let sent = [(&plain, 8), (&named, 8), (&plain, abi::NO_WAIT | 8)].map(|(h, desc)| {
        let mut x = marked();
        x[..2].copy_from_slice(&[h.raw().0, desc]);
        failed(raw_send(x), x, Error::PeerClosed)
    });
    close(plain)?;
    close(named)?;
    check(
        sent.iter().all(|&ok| ok),
        "send to a closed channel did not fail with PEER_CLOSED alone",
    )
}

/// Spec 15.2 (refusals): a request that waits in the queue of a channel
/// whose last handle with RECEIVE goes gets PEER_CLOSED (spec 6.8): a
/// client below init sends through a copy with SEND and waits; init closes
/// its own handle, and the stage Close wakes the client, whose send fails
/// with PEER_CLOSED in x0 alone.
fn queued_client_gets_peer_closed_on_close() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let sender = copy(&c, Rights::SEND)?;
    let mut x = marked();
    x[..2].copy_from_slice(&[sender.raw().0, 8]);
    for (r, v) in RAW.iter().zip(x) {
        r.store(v, Relaxed);
    }
    let t = spawn(0, raw_client, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    let waited = !ended(0);
    close(c)?;
    let_run()?;
    close(t)?;
    close(sender)?;
    check(waited, "the client did not wait")?;
    let after = result(0);
    check(
        ended(0) && after[0] == Error::PeerClosed.code() && after[1..10] == x[1..],
        "the queued client did not get PEER_CLOSED alone when the channel closed",
    )
}

/// Spec 15.2 (refusals): a request a service took outlives the close of
/// its channel (spec 6.8): init takes the request of a client, closes the
/// channel's last handle with RECEIVE, and answers; the client gets the
/// reply.
fn accepted_request_outlives_the_close() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let sender = copy(&c, Rights::SEND)?;
    HANDLES[0].store(sender.raw().0, Relaxed);
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c);
    close(c)?;
    let replied = token.map(|token| token.reply(&request(0)));
    close(t)?;
    close(sender)?;
    let mut want = [0; 10];
    want[1] = 16;
    want[2..].copy_from_slice(&words(&request(0)));
    check(
        replied == Ok(Ok(())) && ended(0) && result(0)[..10] == want,
        "the reply to a request taken before the close did not reach the client",
    )
}

/// The stage Close runs at the level of the top thread that waits (spec
/// 7.7): a thread at 30 waits in receive on a channel whose last handle
/// with RECEIVE lies in a child with no code; a thread at 5 kills the
/// child, whose teardown runs at 5, closes the channel with the child's
/// handles and then tells a thread at 20 of the end through the exit
/// channel. The waiter wakes with PEER_CLOSED before the thread at 20 runs.
/// Then the same with a sender at 30 whose request waits in the queue.
fn close_runs_at_the_top_waiter() -> Outcome {
    [false, true].into_iter().try_for_each(close_round)
}

/// A round of `close_runs_at_the_top_waiter`: the thread at 30 sends when
/// `sender`, and receives otherwise.
fn close_round(sender: bool) -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let moved = copy(&c, Rights::RECEIVE | Rights::TRANSFER)?;
    let (exits, name) = exit_channel()?;
    let child = sys::process_create_with(CHILD_QUOTA, 16, LOW, Some((&name, QUIET)), Some(moved))
        .map_err(|_| "process_create with a start channel failed")?;
    let send = copy(&c, Rights::SEND)?;
    let waits = if sender { &send } else { &c };
    HANDLES[0].store(waits.raw().0, Relaxed);
    HANDLES[1].store(exits.raw().0, Relaxed);
    HANDLES[2].store(child.raw().0, Relaxed);
    let entry = if sender {
        send_then_look
    } else {
        receive_then_look
    };
    let w = spawn(0, entry, 0, HIGH, Policy::Fifo)?;
    // The child's copy is the last handle with RECEIVE from now on.
    close(c)?;
    let m = spawn(1, mark_at_notice, 1, TEST_PRIORITY, Policy::Fifo)?;
    let k = spawn(2, kill_child, 2, LOW, Policy::Fifo)?;
    let_run()?;
    for h in [w, m, k] {
        close(h)?;
    }
    for h in [send, exits, name] {
        close(h)?;
    }
    close(child)?;
    let got = result(0);
    check(
        ended(0) && got[0] == Error::PeerClosed.code() && result(2)[0] == 0,
        "the thread that waited did not get PEER_CLOSED, or process_kill failed",
    )?;
    check(
        got[1] == 0 && mark(1) == 1,
        "the thread at 20 ran before the stage Close woke the thread at 30",
    )
}

/// Waits in receive on the channel HANDLES holds for `slot`; leaves the
/// error code of the call and mark 1 at its return in `result`; ends.
extern "C" fn receive_then_look(slot: u64) -> ! {
    let s = slot as usize;
    let code = sys::receive(&handle(s)).map_or_else(|e| e.code(), |_| 0);
    record(s, &[code, mark(1)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// The same with send of request(slot).
extern "C" fn send_then_look(slot: u64) -> ! {
    let s = slot as usize;
    let code = sys::send(&handle(s), &request(s)).map_or_else(|e| e.code(), |_| 0);
    record(s, &[code, mark(1)]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Waits in receive on the channel HANDLES holds for `slot`, sets mark 1
/// at its return, and ends.
extern "C" fn mark_at_notice(slot: u64) -> ! {
    let _ = sys::receive(&handle(slot as usize));
    MARKS[1].store(1, Relaxed);
    sys::thread_exit()
}

/// Kills the process whose handle HANDLES holds for `slot`, leaves the
/// code of the call in `result`, and ends.
extern "C" fn kill_child(slot: u64) -> ! {
    let s = slot as usize;
    let child = Handle::<Process>::from_raw(abi::Handle(HANDLES[s].load(Relaxed)));
    let code = sys::process_kill(&child).map_or_else(|e| e.code(), |()| 0);
    record(s, &[code]);
    sys::thread_exit()
}

/// CLIENT_GONE comes after the requests of its label (spec 5.3): a client
/// at 10 sends through a copy with a label, whose session's slot has
/// priority 40, and init closes the copy, the last one, while the request
/// waits in the queue. Init takes the request first, then CLIENT_GONE
/// with the label: the request held a copy until init took it.
fn client_gone_comes_after_queued_requests() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, 40)?;
    HANDLES[0].store(named.raw().0, Relaxed);
    let t = spawn(0, client, 0, LEVEL, Policy::Fifo)?;
    let_run()?;
    close(named)?;
    // The last receive finds nothing, which ends the boost of CLIENT_GONE.
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let label = match &got[0] {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    };
    let after =
        got[1] == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)) && got[2] == Err(Error::WouldBlock);
    let replied = answer_all(got);
    let_run()?;
    close(t)?;
    close(c)?;
    check(
        label == CLIENT_LABEL,
        "the request did not come first, with its label",
    )?;
    check(after, "CLIENT_GONE did not come after the request")?;
    check(
        replied && ended(0) && result(0)[0] == 0,
        "the client did not get the reply",
    )
}

/// thread_set_priority moves a thread that waits in send in the channel's
/// queue by the rules of the ready queue (spec 6.3): clients at 10, 10 and
/// 11 send in that order through copies labelled 1, 2 and 3; init raises
/// the second to 11, which puts it at the tail of 11, behind the third,
/// and takes the requests: 3, 2, 1.
fn set_priority_moves_a_waiting_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let mut copies = [const { None }; 3];
    for (i, h) in copies.iter_mut().enumerate() {
        let s = session(&c, Rights::SEND, i as u64 + 1, QUIET)?;
        HANDLES[i].store(s.raw().0, Relaxed);
        *h = Some(s);
    }
    let mut threads = [const { None }; 3];
    for (i, level) in [LEVEL, LEVEL, LEVEL + 1].into_iter().enumerate() {
        threads[i] = Some(spawn(i, client, i as u64, level, Policy::Fifo)?);
        // Each sends before the next, once init lets it.
        let_run()?;
    }
    let raised = threads[1]
        .as_ref()
        .map(|t| sys::thread_set_priority(t, LEVEL + 1, Policy::Fifo));
    let got = [(); 3].map(|()| sys::try_receive(&c));
    let labels = got.each_ref().map(|g| match g {
        Ok(Received::Message { label, .. }) => *label,
        _ => 0,
    });
    let replied = answer_all(got);
    let_run()?;
    for h in threads.into_iter().flatten() {
        close(h)?;
    }
    for h in copies.into_iter().flatten() {
        close(h)?;
    }
    close(c)?;
    check(
        raised == Some(Ok(())) && labels == [3, 2, 1],
        "the raised sender did not move to the tail of its new level",
    )?;
    check(
        replied && (0..3).all(ended),
        "a client did not get its reply",
    )
}

/// The service of `notification_boost_outlives_an_older_reply`: takes a
/// request on the channel HANDLES holds for `slot`, then a notification on
/// it; answers the request and sets SEEN to 1 more than mark 1; ends.
extern "C" fn answer_after_notice(slot: u64) -> ! {
    let c = handle(slot as usize);
    if let Ok(Received::Message { token, .. }) = sys::receive(&c) {
        let _ = sys::receive(&c);
        let _ = token.reply(&[]);
        SEEN.store(mark(1) + 1, Relaxed);
    }
    sys::thread_exit()
}

/// A reply to an older request keeps the boost of a notification taken
/// after it (spec 6.6): a service at 10 takes the request of a client at
/// 15 and then, in its next receive, a notification of the channel's slot
/// at 30; it answers the request and sets its mark still at 30, before a
/// ready thread at init's level runs. That receive ended the boost by the
/// request and forgot its token.
fn notification_boost_outlives_an_older_reply() -> Outcome {
    reset_results();
    let c = channel(HIGH)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let s = spawn(0, answer_after_notice, 0, LEVEL, Policy::Fifo)?;
    let k = spawn(1, client, 1, 15, Policy::Fifo)?;
    // The client's request waits until the service takes it, and the
    // service waits again.
    let_run()?;
    let peer = spawn(2, add_mark, 1, TEST_PRIORITY, Policy::Fifo)?;
    let posted = sys::notify(&c, 1);
    let seen = SEEN.load(Relaxed);
    let_run()?;
    for h in [s, k, peer] {
        close(h)?;
    }
    close(c)?;
    check(
        posted.is_ok() && seen == 1,
        "the reply to the older request ended the boost of the notification",
    )?;
    check(
        ended(1) && mark(1) == 1,
        "the client did not get its reply, or the thread at 20 did not end",
    )
}

/// More threads than the system has numbers (spec 8: 1024).
const PAST_NUMBERS: usize = 1100;

/// The handles `exited_threads_hold_no_numbers` keeps.
static HELD: [AtomicU64; PAST_NUMBERS] = [const { AtomicU64::new(0) }; PAST_NUMBERS];

/// A thread gives its number back as it ends (spec 6.1, 8): init makes
/// more threads than the system has numbers, one after another, each above
/// init, so that it runs and exits at once, and keeps its handle; none
/// fails with LIMIT_REACHED. Then init closes the handles.
fn exited_threads_hold_no_numbers() -> Outcome {
    reset_marks();
    let mut made = Ok(());
    for held in &HELD {
        let t = thread(0, add_mark, 0, HIGH, Policy::Fifo).and_then(|t| {
            let started = sys::thread_start(&t);
            held.store(t.raw().0, Relaxed);
            started.map_err(|_| "thread_start failed")
        });
        if let Err(why) = t {
            made = Err(why);
            break;
        }
    }
    for held in &HELD {
        let h = held.swap(0, Relaxed);
        if h != 0 {
            close(Handle::<Thread>::from_raw(abi::Handle(h)))?;
        }
    }
    check(
        made.is_ok() && mark(0) == PAST_NUMBERS as u64,
        "a thread that exited kept its number: thread_create failed",
    )
}

// The message buffer (spec 6.2): TPIDRRO_EL0 holds its address; bytes 64
// and up of a message go from the sender's buffer into the receiver's, at
// their offsets, and the kernel leaves bytes 0-63 and the bytes past the
// length alone.

/// The seeds of the patterns of the buffer tests: init's buffer, a
/// client's buffer, and the bytes of a message.
const INIT_SEED: u8 = 0x11;
const CLIENT_SEED: u8 = 0x5B;
const MESSAGE_SEED: u8 = 0xC3;

/// MESSAGE_MAX bytes that differ from those of another seed at each
/// offset.
fn pattern(seed: u8) -> [u8; abi::MESSAGE_MAX] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ (i >> 8) as u8 ^ seed)
}

/// Fills the data of the calling thread's message buffer with
/// pattern(seed).
fn fill_buffer(seed: u8) {
    rt::msgbuf::write(0, &pattern(seed));
}

/// The data of the calling thread's message buffer.
fn buffer_data() -> [u8; abi::MESSAGE_MAX] {
    let mut data = [0; abi::MESSAGE_MAX];
    rt::msgbuf::read(0, &mut data);
    data
}

/// Leaves the address of its message buffer in mark `i` and ends.
extern "C" fn note_buffer(i: u64) -> ! {
    MARKS[i as usize].store(rt::msgbuf::address() as u64, Relaxed);
    sys::thread_exit()
}

/// Spec 6.2: TPIDRRO_EL0 holds the address of the thread's message buffer:
/// abi::INIT_MSGBUF for init's first thread, and for a thread
/// thread_create made, the page it named.
fn buffer_address_is_in_tpidrro() -> Outcome {
    reset_marks();
    let own = rt::msgbuf::address();
    let t = spawn(0, note_buffer, 0, HIGH, Policy::Fifo)?;
    close(t)?;
    check(
        own == abi::INIT_MSGBUF as usize,
        "init's TPIDRRO_EL0 does not hold its message buffer",
    )?;
    check(
        mark(0) == buffer(0) as u64,
        "a new thread's TPIDRRO_EL0 does not hold its message buffer",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED),
/// sends the first `len` bytes of pattern(MESSAGE_SEED) through the
/// channel HANDLES holds for it, and leaves the code and the length of
/// the reply in `result`; ends.
extern "C" fn pattern_client(len: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    match sys::send(&handle(0), &pattern(MESSAGE_SEED)[..len as usize]) {
        Ok(reply) => record(0, &[0, reply.len as u64]),
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a request of 1024 bytes arrives whole (spec 6.1,
/// 6.2): a client above init sends pattern bytes, and init takes the
/// request without waiting: its buffer holds all of them.
fn long_request_arrives_whole() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let max = abi::MESSAGE_MAX;
    let t = spawn(0, pattern_client, max as u64, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let whole = matches!(got, Ok(Received::Message { len, .. }) if len == max)
        && buffer_data() == pattern(MESSAGE_SEED);
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    check(whole, "the request of 1024 bytes did not arrive whole")?;
    check(
        replied && ended(0) && result(0)[..2] == [0, 0],
        "the client did not get the reply",
    )
}

/// A client in slot 0 that sends request(0) through the channel HANDLES
/// holds for it and, once the reply came, leaves in `result` the code, the
/// length of the reply and 1 when its buffer holds pattern(MESSAGE_SEED);
/// ends.
extern "C" fn client_looks(_: u64) -> ! {
    match sys::send(&handle(0), &request(0)) {
        Ok(reply) => {
            let whole = buffer_data() == pattern(MESSAGE_SEED);
            record(0, &[0, reply.len as u64, u64::from(whole)]);
        }
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a reply of 1024 bytes arrives whole: a client
/// above init sends 16 bytes, init answers with pattern bytes, and the
/// client's buffer holds all of them when its send returns.
fn long_reply_arrives_whole() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, client_looks, 0, HIGH, Policy::Fifo)?;
    let replied = take_token(&c).map(|token| token.reply(&pattern(MESSAGE_SEED)));
    close(t)?;
    close(c)?;
    check(
        replied == Ok(Ok(())) && ended(0),
        "the reply failed or did not reach the client",
    )?;
    check(
        result(0)[..3] == [0, abi::MESSAGE_MAX as u64, 1],
        "the reply of 1024 bytes did not arrive whole",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED),
/// sends 64 bytes through the channel HANDLES holds for it and leaves in
/// `result` the code and 1 when its buffer still holds the pattern after
/// the reply; ends.
extern "C" fn short_client(_: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    match sys::send(&handle(0), &[0xC5; abi::INLINE_MAX]) {
        Ok(_) => record(0, &[0, u64::from(buffer_data() == pattern(CLIENT_SEED))]),
        Err(e) => record(0, &[e.code()]),
    }
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// Messages of 64 bytes leave the buffers alone (spec 6.2): they travel in
/// x2-x9 only. Init's buffer and a client's hold patterns; the client
/// sends 64 bytes, init takes them and answers with 64: both buffers keep
/// their patterns.
fn short_message_leaves_the_buffers_alone() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    fill_buffer(INIT_SEED);
    let t = spawn(0, short_client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c);
    let kept = buffer_data() == pattern(INIT_SEED);
    let replied = token.map(|token| token.reply(&[0x3C; abi::INLINE_MAX]));
    close(t)?;
    close(c)?;
    check(kept, "a request of 64 bytes changed the receiver's buffer")?;
    check(
        replied == Ok(Ok(())) && ended(0) && result(0)[..2] == [0, 1],
        "a reply of 64 bytes changed the client's buffer",
    )
}

/// A client in slot 0 that fills its buffer with pattern(CLIENT_SEED) and
/// sends 8 bytes with raw registers through the channel HANDLES holds for
/// it; then leaves in `result` x0-x2 of the call and 1 when its buffer
/// holds bytes 64-127 of pattern(INIT_SEED) and its own pattern elsewhere;
/// ends.
extern "C" fn raw_looker(_: u64) -> ! {
    fill_buffer(CLIENT_SEED);
    let mut x = marked();
    x[..2].copy_from_slice(&[HANDLES[0].load(Relaxed), 8]);
    let after = raw_send(x);
    let mut want = pattern(CLIENT_SEED);
    want[64..128].copy_from_slice(&pattern(INIT_SEED)[64..128]);
    let seen = u64::from(buffer_data() == want);
    record(0, &[after[0], after[1], after[2], seen]);
    ENDED[0].store(1, Relaxed);
    sys::thread_exit()
}

/// The kernel leaves bytes 0-63 of the buffers alone (spec 6.2): they
/// travel in x2-x9. A client fills its buffer with a pattern and sends;
/// init fills its own with another and answers with 128 bytes through raw
/// registers, every bit of x2-x9 set. The client gets init's registers in
/// x2-x9 and bytes 64-127 of init's buffer; its own bytes 0-63 and past
/// 127 stay.
fn kernel_leaves_bytes_0_to_63_of_the_buffer() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let t = spawn(0, raw_looker, 0, HIGH, Policy::Fifo)?;
    fill_buffer(INIT_SEED);
    let mut x = [u64::MAX; 10];
    x[1] = 128;
    let after = take_token(&c).map(|token| {
        x[0] = token.raw();
        raw_reply(x)
    });
    close(t)?;
    close(c)?;
    check(
        after.is_ok_and(|a| a[0] == 0) && ended(0),
        "the reply failed or did not reach the client",
    )?;
    check(
        result(0)[..4] == [0, 128, u64::MAX, 1],
        "the kernel touched bytes 0-63 or past the length of a buffer",
    )
}

/// The receiver's buffer past the length stays as it was (spec 6.2): init's
/// buffer holds a pattern; a client, its buffer full of another, sends 100
/// bytes, and init takes them: its buffer holds the 100 bytes and its own
/// pattern after them.
fn bytes_past_the_length_stay() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    fill_buffer(INIT_SEED);
    let t = spawn(0, pattern_client, 100, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came = matches!(got, Ok(Received::Message { len: 100, .. }));
    let data = buffer_data();
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    let mut want = pattern(INIT_SEED);
    want[..100].copy_from_slice(&pattern(MESSAGE_SEED)[..100]);
    check(
        came && data == want,
        "a request of 100 bytes changed the receiver's buffer past its length",
    )?;
    check(
        replied && ended(0) && result(0)[..2] == [0, 0],
        "the client did not get the reply",
    )
}

// Handles in messages (spec 6.1, 6.2): a request or a reply carries up to
// four handles, whose values lie in the message buffer; they move from the
// sender's table into the receiver's with their rights and labels, and the
// buffer tells the receiver the kind and the rights of each. They stay
// with the sender when a check of the call fails, and go when the call
// fails with PEER_CLOSED, LIMIT_REACHED or NO_MEMORY.

/// The handles `handle_client` sends, and how many of them.
static GIVEN: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static GIVEN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Entries init's table has at most (kcore::handles::MAX_HANDLES): its
/// limit, which the kernel sets.
const INIT_HANDLES: usize = 16384;

/// The copies `fill_table` made, which `empty_table` closes.
static FILLED: [AtomicU64; INIT_HANDLES] = [const { AtomicU64::new(0) }; INIT_HANDLES];

/// Values that name no live handle: the next generation of entry 1000 of
/// init's table, which no test reaches (spec 5.1).
const STALE: abi::Handle = abi::Handle::new(1000, 1 << 40);

/// Sets the handles `handle_client` sends.
fn give(handles: &[abi::Handle]) {
    for (g, h) in GIVEN.iter().zip(handles) {
        g.store(h.0, Relaxed);
    }
    GIVEN_COUNT.store(handles.len() as u64, Relaxed);
}

/// A client in `slot` that sends request(slot) with the handles GIVEN
/// holds through the channel HANDLES holds for it, and leaves in `result`
/// the code, the length and the count of handles of the reply, then the
/// value and the info word of each handle the reply brought; ends.
extern "C" fn handle_client(slot: u64) -> ! {
    let s = slot as usize;
    let n = GIVEN_COUNT.load(Relaxed) as usize;
    let handles: [abi::Handle; 4] = core::array::from_fn(|i| abi::Handle(GIVEN[i].load(Relaxed)));
    match sys::send_handles(&handle(s), &request(s), &handles[..n]) {
        Ok(reply) => {
            let mut w = [0; 11];
            w[1] = reply.len as u64;
            w[2] = reply.handles as u64;
            for i in 0..reply.handles {
                let (h, (kind, rights)) = rt::msgbuf::handle(i);
                w[3 + 2 * i] = h.0;
                w[4 + 2 * i] = abi::msgbuf::info(kind, rights);
            }
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// handle_close with the value `h`, for values that must be bad.
fn close_raw(h: abi::Handle) -> Result<(), Error> {
    Handle::<Channel>::from_raw(h).close()
}

/// Whether each of `handles` is gone: closing it is BAD_HANDLE.
fn all_gone(handles: &[abi::Handle]) -> bool {
    handles
        .iter()
        .all(|&h| close_raw(h) == Err(Error::BadHandle))
}

/// A copy of `h` with `rights` as a raw value, which the test hands the
/// kernel in a message.
fn copy_raw<K>(h: &Handle<K>, rights: Rights) -> Result<abi::Handle, &'static str> {
    copy(h, rights).map(|c| c.raw())
}

/// x0-x9 of a raw send through `h` of 8 bytes and `handles`, whose values
/// go into the message buffer, the rest marked.
fn handle_regs(h: abi::Handle, handles: &[abi::Handle], flags: u64) -> Regs {
    rt::msgbuf::put_handles(handles);
    let mut x = marked();
    x[..2].copy_from_slice(&[
        h.0,
        8 | (handles.len() as u64) << abi::HANDLES_SHIFT | flags,
    ]);
    x
}

/// Fills init's table with copies of the system resource without rights
/// until it has room for `room` handles more; returns how many copies it
/// keeps, which `empty_table` closes.
fn fill_table(room: usize) -> Result<usize, &'static str> {
    let mut n = 0;
    loop {
        match sys::handle_duplicate(&init::RESOURCE, Rights::NONE) {
            Ok(h) => FILLED[n].store(h.raw().0, Relaxed),
            Err(Error::LimitReached) => break,
            Err(_) => return Err("handle_duplicate failed"),
        }
        n += 1;
    }
    for _ in 0..room {
        n -= 1;
        close_raw(abi::Handle(FILLED[n].load(Relaxed))).map_err(|_| "handle_close failed")?;
    }
    Ok(n)
}

/// Closes the first `n` copies of `fill_table`.
fn empty_table(n: usize) -> Outcome {
    FILLED[..n].iter().try_for_each(|h| {
        close_raw(abi::Handle(h.load(Relaxed))).map_err(|_| "handle_close failed")
    })
}

/// Spec 15.2 (messages): handles move with a request (spec 6.1, 6.2). A
/// client above init sends a copy of a channel, a timer, init's process
/// and the system resource, each with TRANSFER and some other rights;
/// init takes the request without waiting: four handles, whose info words
/// give the kind and the rights of each, the same as the client's. The
/// client's values are gone from the table (BAD_HANDLE), and the new ones
/// live.
fn handles_move_with_a_request() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let tm = timer(&e)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let rights = [
        Rights::SEND | Rights::NOTIFY | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
        Rights::DEBUG | Rights::TRANSFER,
    ];
    let sent = [
        copy_raw(&e, rights[0])?,
        copy_raw(&tm, rights[1])?,
        copy_raw(&init::PROCESS, rights[2])?,
        copy_raw(&init::RESOURCE, rights[3])?,
    ];
    give(&sent);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came: [_; 4] = core::array::from_fn(rt::msgbuf::handle);
    let kinds = [
        abi::ObjectKind::Channel,
        abi::ObjectKind::Timer,
        abi::ObjectKind::Process,
        abi::ObjectKind::Resource,
    ];
    let four = matches!(got, Ok(Received::Message { handles: 4, .. }));
    let told = (0..4).all(|i| came[i].1 == (kinds[i], rights[i]));
    let replied = answer_all([got]);
    let gone = all_gone(&sent);
    let live = came.iter().all(|&(h, _)| close_raw(h).is_ok());
    close(t)?;
    for h in [c, e] {
        close(h)?;
    }
    close(tm)?;
    check(
        four && told,
        "the request did not bring four handles with their kinds and rights",
    )?;
    check(
        gone && live,
        "the handles did not leave the client's values for new ones",
    )?;
    check(
        replied && ended(0) && result(0)[..3] == [0, 0, 0],
        "the client did not get the reply",
    )
}

/// Spec 15.2 (messages): handles move with a reply. A client above init
/// sends; init answers with a copy of a channel and one of the client's
/// thread: the client's send brings two handles, whose values and info
/// words it leaves; init's values are gone, and the client's live.
fn handles_move_with_a_reply() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[]);
    let rights = [
        Rights::NOTIFY | Rights::TRANSFER,
        Rights::MANAGE | Rights::TRANSFER,
    ];
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let sent = [copy_raw(&e, rights[0])?, copy_raw(&t, rights[1])?];
    let replied = take_token(&c)?.reply_handles(&[], &sent);
    let got = result(0);
    let gone = all_gone(&sent);
    let live = [got[3], got[5]]
        .iter()
        .all(|&h| close_raw(abi::Handle(h)).is_ok());
    close(t)?;
    close(c)?;
    close(e)?;
    let infos = [
        abi::msgbuf::info(abi::ObjectKind::Channel, rights[0]),
        abi::msgbuf::info(abi::ObjectKind::Thread, rights[1]),
    ];
    check(
        replied.is_ok() && ended(0) && got[..3] == [0, 0, 2],
        "the reply did not bring two handles",
    )?;
    check(
        [got[4], got[6]] == infos,
        "the handles of the reply came with other kinds or rights",
    )?;
    check(
        gone && live,
        "the handles did not leave init's values for the client's",
    )
}

/// Spec 15.2 (messages): rights stay as narrow as the handle that moved
/// (spec 5.2, 6.1). A client sends a copy of a channel with SEND and
/// TRANSFER only; init's new handle says so, receives through it with
/// ACCESS_DENIED, and cannot copy it without DUPLICATE.
fn rights_stay_narrowed() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let narrow = Rights::SEND | Rights::TRANSFER;
    give(&[copy_raw(&c, narrow)?]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let (h, info) = rt::msgbuf::handle(0);
    let came = Handle::<Channel>::from_raw(h);
    let refused = sys::try_receive(&came) == Err(Error::AccessDenied)
        && sys::handle_duplicate(&came, Rights::NONE) == Err(Error::AccessDenied);
    let replied = answer_all([got]);
    close(came)?;
    close(t)?;
    close(c)?;
    check(
        info == (abi::ObjectKind::Channel, narrow),
        "the handle came with other rights",
    )?;
    check(refused, "a right the handle lacked came with it")?;
    check(replied && ended(0), "the client did not get the reply")
}

/// Spec 15.2 (messages): a label travels with its handle, and the copies
/// of its session stay as they were (spec 5.3): a client sends the only
/// copy with a label of a channel; no CLIENT_GONE comes meanwhile, a
/// notification through init's new handle comes with the label, and
/// CLIENT_GONE comes once init closes it.
fn label_travels_with_its_handle() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let named = session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?;
    give(&[named.raw()]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let (h, info) = rt::msgbuf::handle(0);
    let came = Handle::<Channel>::from_raw(h);
    let early = sys::try_receive(&e);
    let posted = sys::notify(&came, 1);
    let heard = take_one(&e);
    close(came)?;
    let gone = take_one(&e);
    let replied = answer_all([got]);
    close(t)?;
    close(c)?;
    close(e)?;
    check(
        early == Err(Error::WouldBlock),
        "the session's CLIENT_GONE came while its handle moved",
    )?;
    check(
        info == (abi::ObjectKind::Channel, Rights::NOTIFY | Rights::TRANSFER),
        "a handle with a label came as another kind",
    )?;
    check(
        posted.is_ok() && heard == Ok(labelled(CLIENT_LABEL, 1, 1)),
        "a notification through the handle that moved lost its label",
    )?;
    check(
        gone == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "CLIENT_GONE did not come once the handle that moved went",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// The last handle with RECEIVE moves without closing its channel (spec
/// 5.3, 6.1): a client sends it; a copy with NOTIFY notifies meanwhile,
/// and init receives the notification through its new handle; once init
/// closes that, notify fails with PEER_CLOSED.
fn receive_right_moves_without_closing_the_channel() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let n = copy(&e, Rights::NOTIFY)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[e.raw()]);
    let t = spawn(0, handle_client, 0, HIGH, Policy::Fifo)?;
    let got = sys::try_receive(&c);
    let came = Handle::<Channel>::from_raw(rt::msgbuf::handle(0).0);
    let open = sys::notify(&n, 1);
    let heard = take_one(&came);
    close(came)?;
    let shut = sys::notify(&n, 1);
    let replied = answer_all([got]);
    close(n)?;
    close(t)?;
    close(c)?;
    check(
        open.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the channel closed when its last handle with RECEIVE moved",
    )?;
    check(
        shut == Err(Error::PeerClosed),
        "the channel stayed open once the handle that moved went",
    )?;
    check(replied && ended(0), "the client did not get the reply")
}

/// The handles stay with the sender when a check of the call fails (spec
/// 6.1, 11): a bad x0, one of another kind or without SEND, a handle of the
/// message without TRANSFER or bad after good ones, and NO_WAIT with no
/// receiver fail send, as a token that names nothing fails reply; each
/// changes x0 alone, and the good handles still close.
fn a_failed_check_takes_no_handle() -> Outcome {
    let c = channel(QUIET)?;
    let notify_only = copy(&c, Rights::NOTIFY)?;
    let e = channel(QUIET)?;
    let good = [
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
    ];
    let held = copy_raw(&e, Rights::NOTIFY)?;
    let [a, b] = good;
    let cases = [
        (STALE, &[a, b][..], 0, Error::BadHandle),
        (init::PROCESS.raw(), &[a, b], 0, Error::WrongType),
        (notify_only.raw(), &[a, b], 0, Error::AccessDenied),
        (c.raw(), &[a, b, held], 0, Error::AccessDenied),
        (c.raw(), &[a, b, STALE], 0, Error::BadHandle),
        (c.raw(), &[a, b], abi::NO_WAIT, Error::WouldBlock),
    ];
    let sent = cases.map(|(h, handles, flags, error)| {
        let x = handle_regs(h, handles, flags);
        failed(raw_send(x), x, error)
    });
    let x = handle_regs(abi::Handle(1 << 16), &[a, b], 0);
    let replied = failed(raw_reply(x), x, Error::BadState);
    let kept = [a, b, held].iter().all(|&h| close_raw(h).is_ok());
    close(notify_only)?;
    close(c)?;
    close(e)?;
    check(
        sent.iter().all(|&ok| ok),
        "send with a failing check did not fail as it should, x0 alone",
    )?;
    check(
        replied,
        "reply with a bad token did not fail with BAD_STATE alone",
    )?;
    check(kept, "a call that failed a check took a handle")
}

/// PEER_CLOSED takes the handles (spec 6.1): send with two handles through
/// a copy of a channel whose last handle with RECEIVE went fails with
/// PEER_CLOSED in x0 alone, and the handles are gone.
fn peer_closed_takes_the_handles() -> Outcome {
    let c = channel(QUIET)?;
    let left = copy(&c, Rights::SEND)?;
    let e = channel(QUIET)?;
    let sent = [
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
        copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?,
    ];
    close(c)?;
    let x = handle_regs(left.raw(), &sent, 0);
    let after = raw_send(x);
    let gone = all_gone(&sent);
    close(left)?;
    close(e)?;
    check(
        failed(after, x, Error::PeerClosed),
        "send to a closed channel did not fail with PEER_CLOSED alone",
    )?;
    check(gone, "PEER_CLOSED left the handles with the sender")
}

/// A receiver whose table has no room fails the sender (spec 6.1): a
/// thread of init waits in receive, and init fills its own table but for
/// three entries; send with four handles fails with LIMIT_REACHED in x0
/// alone, the handles are gone, and the receiver waits on: a request with
/// no handles and NO_WAIT then reaches it.
fn full_waiting_receiver_fails_the_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let sent: [abi::Handle; 4] = [
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    let n = fill_table(3)?;
    let x = handle_regs(c.raw(), &sent, 0);
    let after = raw_send(x);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let waited = result(0) == [0; 12];
    let got = sys::try_send(&c, &request(1));
    let_run()?;
    close(w)?;
    close(c)?;
    check(
        failed(after, x, Error::LimitReached),
        "send to a receiver with no room did not fail with LIMIT_REACHED alone",
    )?;
    check(
        gone && waited,
        "the handles stayed, or the receiver took the request",
    )?;
    check(
        got.is_ok() && result(0)[..2] == [0, 16] && result(0)[2..4] == words(&request(1))[..2],
        "the receiver did not take the next request",
    )
}

/// A receiver whose quota falls short for a chunk of its table fails the
/// sender (spec 6.1, 7.5): a thread of init waits in receive; init fills
/// its table to the end of a page of its pool of blocks, a child takes the
/// rest of init's quota, and send with four handles fails with NO_MEMORY in
/// x0 alone; the handles are gone, and the receiver waits on: a request
/// with no handles and NO_WAIT then reaches it.
fn receiver_quota_fails_the_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    let w = spawn(0, server, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let sent: [abi::Handle; 4] = [
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    // A free place in init's pool of shells for the child below.
    close(child(LOW)?)?;
    let n = fill_to_a_page()?;
    let own = sys::process_memory(&init::PROCESS).map_err(|_| "PROCESS_MEMORY of init failed")?;
    let rest = (own.quota - own.returned - own.used) / PAGE as u64 * PAGE as u64;
    let hog = sys::process_create(rest, 16, LOW);
    let x = handle_regs(c.raw(), &sent, 0);
    let after = raw_send(x);
    let made = hog.is_ok();
    if let Ok(hog) = hog {
        close(hog)?;
    }
    empty_table(n)?;
    let gone = all_gone(&sent);
    let waited = result(0) == [0; 12];
    let got = sys::try_send(&c, &request(1));
    let_run()?;
    close(w)?;
    close(c)?;
    check(made, "the child that takes init's quota was not made")?;
    check(
        failed(after, x, Error::NoMemory),
        "send to a receiver with no quota for a chunk did not fail with NO_MEMORY alone",
    )?;
    check(
        gone && waited,
        "the handles stayed, or the receiver took the request",
    )?;
    check(
        got.is_ok() && result(0)[..2] == [0, 16],
        "the receiver did not take the next request",
    )
}

/// Fills init's table to the end of a page of its pool of blocks, which
/// holds two chunks of 64 entries (spec 5.1, 7.8), but for one entry: the
/// copy that makes init pay for a page starts the page's first chunk, and
/// 126 more fill it and the second but for its last entry. Returns the
/// copies, which `empty_table` closes; it closes them itself on a failure.
fn fill_to_a_page() -> Result<usize, &'static str> {
    let used = || sys::process_memory(&init::PROCESS).map(|m| m.used);
    let mut n = 0;
    let mut left = None;
    while left != Some(0) {
        let before = used();
        let Ok(h) = sys::handle_duplicate(&init::RESOURCE, Rights::NONE) else {
            empty_table(n)?;
            return Err("handle_duplicate failed");
        };
        FILLED[n].store(h.raw().0, Relaxed);
        n += 1;
        left = match left {
            Some(k) => Some(k - 1),
            None if used() != before => Some(126),
            None => None,
        };
    }
    Ok(n)
}

/// A request whose handles do not fit fails its sender, and receive takes
/// the next head (spec 6.1): a client below init sends four handles
/// through a copy with a label, and another one no handles through the
/// channel, and both wait; init closes the copy, so the first request
/// holds the session's last copy (spec 5.3), fills its table and receives
/// without waiting: the first client gets LIMIT_REACHED, and init gets the
/// second request. Before the first client runs again, its handles are
/// gone, the only copy of a session of another channel among them, whose
/// CLIENT_GONE comes there; and so is the copy its request held, whose
/// CLIENT_GONE comes after the second request.
fn queued_request_that_does_not_fit_fails_its_sender() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let named = session(&c, Rights::SEND, CLIENT_LABEL, QUIET)?;
    HANDLES[0].store(named.raw().0, Relaxed);
    HANDLES[1].store(c.raw().0, Relaxed);
    let sent: [abi::Handle; 4] = [
        session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?.raw(),
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    give(&sent);
    let first = spawn(0, handle_client, 0, LOW, Policy::Fifo)?;
    let_run()?;
    close(named)?;
    let second = spawn(1, client, 1, LOW, Policy::Fifo)?;
    let_run()?;
    let n = fill_table(0)?;
    let got = sys::try_receive(&c);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let dropped = take_one(&e);
    let released = take_one(&c);
    let waited = !ended(0);
    let words_of = match &got {
        Ok(Received::Message { words, .. }) => Some(*words),
        _ => None,
    };
    let replied = answer_all([got]);
    let_run()?;
    close(first)?;
    close(second)?;
    close(c)?;
    close(e)?;
    check(
        ended(0) && result(0)[0] == Error::LimitReached.code(),
        "the sender whose handles did not fit did not get LIMIT_REACHED",
    )?;
    check(waited, "the sender that failed ran before init looked")?;
    check(
        gone && dropped == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the handles of the request that failed stayed with its sender",
    )?;
    check(
        released == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the request that failed kept its copy of the session",
    )?;
    check(
        words_of == Some(words(&request(1))) && replied && ended(1) && result(1)[0] == 0,
        "receive did not take the next request",
    )
}

/// A reply whose handles do not fit fails both sides and uses the token up
/// (spec 6.1): a client above init sends; init fills its table and answers
/// with four handles, the only copy of a session of another channel among
/// them: LIMIT_REACHED for the reply, in x0 alone, and for the client's
/// send; the handles are gone, and CLIENT_GONE comes on the other channel;
/// a second reply with the token is BAD_STATE. Init's next reply, with a
/// handle, brings it to a second client: the reply that failed left
/// nothing on its way.
fn reply_that_does_not_fit_fails_both() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    for h in &HANDLES[..2] {
        h.store(c.raw().0, Relaxed);
    }
    let sent: [abi::Handle; 4] = [
        session(&e, Rights::NOTIFY | Rights::TRANSFER, CLIENT_LABEL, QUIET)?.raw(),
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
        copy_raw(&init::RESOURCE, Rights::TRANSFER)?,
    ];
    let t = spawn(0, client, 0, HIGH, Policy::Fifo)?;
    let token = take_token(&c)?.raw();
    let n = fill_table(0)?;
    let x = handle_regs(abi::Handle(token), &sent, 0);
    let after = raw_reply(x);
    empty_table(n)?;
    let gone = all_gone(&sent);
    let dropped = take_one(&e);
    let mut again = marked();
    again[..2].copy_from_slice(&[token, 0]);
    let second = raw_reply(again);
    give(&[]);
    let next = spawn(1, handle_client, 1, HIGH, Policy::Fifo)?;
    let moved = copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?;
    let replied = take_token(&c)?.reply_handles(&[], &[moved]);
    let came = result(1);
    let live = close_raw(abi::Handle(came[3])).is_ok();
    close(t)?;
    close(next)?;
    close(c)?;
    close(e)?;
    check(
        failed(after, x, Error::LimitReached),
        "a reply with no room at the client did not fail with LIMIT_REACHED alone",
    )?;
    check(
        ended(0) && result(0)[0] == Error::LimitReached.code(),
        "the client's send did not fail with the reply",
    )?;
    check(
        gone && dropped == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the handles of the reply that failed stayed",
    )?;
    check(
        failed(second, again, Error::BadState),
        "the reply that failed left its token",
    )?;
    check(
        replied.is_ok() && ended(1) && came[..3] == [0, 0, 1] && live,
        "the next reply did not bring its handle",
    )
}

/// Rounds of `closed_handle_stays_bad_after_many_transfers`.
const TRANSFERS: u64 = 1000;

/// A client that sends TRANSFERS requests through the channel HANDLES
/// holds for `slot`, each with a new copy of the handle GIVEN holds, the
/// next once the reply came; leaves the first error or 0 in `result`;
/// ends.
extern "C" fn transfers(slot: u64) -> ! {
    let s = slot as usize;
    let object = Handle::<Channel>::from_raw(abi::Handle(GIVEN[0].load(Relaxed)));
    let mut code = 0;
    for _ in 0..TRANSFERS {
        let sent = sys::handle_duplicate(&object, Rights::NOTIFY | Rights::TRANSFER)
            .and_then(|h| sys::send_handles(&handle(s), &[], &[h.raw()]));
        if let Err(e) = sent {
            code = e.code();
            break;
        }
    }
    record(s, &[code]);
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// Spec 15.2 (messages): a handle that was closed stays bad however often
/// the client sends that object again (spec 5.1): a client sends a new copy
/// of a channel 1000 times; init keeps the value of the first handle that
/// came and closes each: the first value is BAD_HANDLE after every
/// transfer, and no later one repeats it.
fn closed_handle_stays_bad_after_many_transfers() -> Outcome {
    reset_results();
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    give(&[e.raw()]);
    let t = spawn(0, transfers, 0, HIGH, Policy::Fifo)?;
    let mut first = None;
    let mut bad = true;
    for round in 0..TRANSFERS {
        let got = sys::try_receive(&c);
        let (h, _) = rt::msgbuf::handle(0);
        let came = matches!(got, Ok(Received::Message { handles: 1, .. }));
        let first = *first.get_or_insert(h);
        bad &= came
            && (round == 0) == (h == first)
            && close_raw(h).is_ok()
            && close_raw(first) == Err(Error::BadHandle);
        if !answer_all([got]) {
            bad = false;
        }
        if !bad {
            break;
        }
    }
    close(t)?;
    close(c)?;
    close(e)?;
    check(
        bad,
        "the value of a handle that was closed came back or named a handle",
    )?;
    check(
        ended(0) && result(0)[0] == 0,
        "the client's transfers failed",
    )
}

/// Spec 15.2 (messages): x0 of send cannot travel in its own message (spec
/// 6.1): send whose handles hold x0, a channel or a copy with a label,
/// fails with INVALID_ARGS in x0 alone, and the handle still works.
fn send_handle_cannot_travel_in_its_own_send() -> Outcome {
    let c = channel(QUIET)?;
    let named = session(&c, Rights::SEND | Rights::TRANSFER, CLIENT_LABEL, QUIET)?;
    let sent = [c.raw(), named.raw()].map(|h| {
        let x = handle_regs(h, &[h], abi::NO_WAIT);
        failed(raw_send(x), x, Error::InvalidArgs)
    });
    let posted = sys::notify(&c, 1);
    let heard = take_one(&c);
    close(named)?;
    let gone = take_one(&c);
    close(c)?;
    check(
        sent.iter().all(|&ok| ok),
        "send took its own handle in its message",
    )?;
    check(
        posted.is_ok() && heard == Ok(unlabeled(1, 1)),
        "the channel's handle did not stay",
    )?;
    check(
        gone == Ok(labelled(CLIENT_LABEL, CLIENT_GONE, 1)),
        "the copy with a label did not stay",
    )
}

/// A value listed twice in a message fails send and reply with
/// INVALID_ARGS before anything is looked up (spec 6.1, 11), x0 alone; the
/// handle stays.
fn same_handle_twice_is_invalid() -> Outcome {
    let c = channel(QUIET)?;
    let e = channel(QUIET)?;
    let a = copy_raw(&e, Rights::NOTIFY | Rights::TRANSFER)?;
    let x = handle_regs(c.raw(), &[a, a], abi::NO_WAIT);
    let sent = failed(raw_send(x), x, Error::InvalidArgs);
    let y = handle_regs(abi::Handle(0), &[a, a], 0);
    let replied = failed(raw_reply(y), y, Error::InvalidArgs);
    let kept = close_raw(a).is_ok();
    close(c)?;
    close(e)?;
    check(sent, "send took a handle listed twice")?;
    check(replied, "reply took a handle listed twice")?;
    check(kept, "a handle listed twice was taken")
}

// Memory objects in messages (spec 6.2, 15.2): a handle to a memory
// object moves with a request or a reply as any handle does, with the
// rights of the copy that moves, and the receiver maps the object into its
// own space with its own mem_map. The services are children with code
// (Role::Service, Role::Provider), which init reaches through a thread of
// its own at HIGH (`memory_client`).

/// The length of the objects of these tests: all a child maps at
/// child::SHARED.
const SHARED_LEN: u64 = (child::SHARED_PAGES * PAGE) as u64;
/// Init's word in a shared object, and the service's.
const INIT_WORD: u64 = 0x1417_5EE5;
const CHILD_WORD: u64 = 0xC41D_5EE5;

/// The two words `memory_client` sends.
static ASKED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// A client in `slot` that sends the words ASKED holds with the handles
/// GIVEN holds through the channel HANDLES holds for it, and leaves in
/// `result` the code of its call, the count of handles of the reply, the
/// value and the info word of its first handle, and its eight words; then
/// ends.
extern "C" fn memory_client(slot: u64) -> ! {
    let s = slot as usize;
    let n = GIVEN_COUNT.load(Relaxed) as usize;
    let handles: [abi::Handle; 4] = core::array::from_fn(|i| abi::Handle(GIVEN[i].load(Relaxed)));
    let words = [
        ASKED[0].load(Relaxed),
        ASKED[1].load(Relaxed),
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let bytes = abi::inline_bytes(&words);
    match sys::send_handles(&handle(s), &bytes[..16], &handles[..n]) {
        Ok(reply) => {
            let mut w = [0; 12];
            w[1] = reply.handles as u64;
            if reply.handles > 0 {
                let (h, (kind, rights)) = rt::msgbuf::handle(0);
                w[2] = h.0;
                w[3] = abi::msgbuf::info(kind, rights);
            }
            w[4..].copy_from_slice(&reply.words);
            record(s, &w);
        }
        Err(e) => record(s, &[e.code()]),
    }
    ENDED[s].store(1, Relaxed);
    sys::thread_exit()
}

/// A child with `role` and its quota answers one request with `words` and
/// `handles`, which a thread of init at HIGH sends (`memory_client`)
/// through a channel whose handle with RECEIVE the child gets, with its
/// own process: what the client got (`result`, the reply's words from 4
/// on) and why the child ended, once it ended.
fn served(
    role: Role,
    words: [u64; 2],
    handles: &[abi::Handle],
) -> Result<([u64; 12], ProcessState), &'static str> {
    reset_results();
    let c = channel(LEVEL)?;
    let send = copy(&c, Rights::SEND)?;
    HANDLES[0].store(send.raw().0, Relaxed);
    for (a, w) in ASKED.iter().zip(words) {
        a.store(w, Relaxed);
    }
    give(handles);
    let kid = Kid::load(quota_of(role), 16, LEVEL)?;
    let asked = kid
        .start()
        .and_then(|()| kid.serve(role, &[], &[Gift::Given(c.raw()), Gift::Own]))
        .and_then(|()| spawn(0, memory_client, 0, HIGH, Policy::Fifo));
    // The child runs once init waits for its end.
    let state = kid.end();
    kid.close()?;
    close(send)?;
    close(asked?)?;
    check(ended(0), "the client did not come back from its request")?;
    Ok((result(0), state?))
}

/// Writes PATTERN plus i into word i of `m`, of SHARED_LEN bytes, through a
/// mapping at WINDOW that goes again; returns the sum of the words.
fn with_pattern(m: &Handle<Memory>) -> Result<u64, &'static str> {
    const PATTERN: u64 = 0x0B1E_C700_0000;
    map(m, 0, SHARED_LEN, WINDOW, Access::ReadWrite)?;
    let mut sum = 0u64;
    for i in 0..SHARED_LEN as usize / 8 {
        let w = PATTERN + i as u64;
        // SAFETY: the window is init's mapping of `m`, read and write.
        unsafe { (WINDOW as *mut u64).add(i).write_volatile(w) };
        sum = sum.wrapping_add(w);
    }
    unmap(WINDOW, SHARED_LEN)?;
    Ok(sum)
}

/// Spec 15.2 (messages), 6.2: a memory object carries a request. Init
/// fills an object with a pattern and sends a copy of its handle with
/// MAP_READ and TRANSFER alone to a service, a child: the info word the
/// child finds with the handle names a memory object with those rights,
/// and the child maps the object R, adds its words up and answers with the
/// sum, the pattern's. The copy left init's table.
fn memory_object_carries_a_request() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    let sum = with_pattern(&m);
    let rights = Rights::MAP_READ | Rights::TRANSFER;
    let sent = copy_raw(&m, rights)?;
    let got = sum.and_then(|_| served(Role::Service, [SHARED_LEN, 0], &[sent]));
    let gone = close_raw(sent) == Err(Error::BadHandle);
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the service did not answer",
    )?;
    check(
        reply[4] == abi::msgbuf::info(abi::ObjectKind::Memory, rights),
        "the handle came to the service as no memory object, or with other rights",
    )?;
    check(
        Ok(reply[5]) == sum,
        "the service did not see the pattern init wrote",
    )?;
    check(gone, "the copy that moved stayed in init's table")
}

/// Spec 15.2 (messages), 5.2, 7.4: a memory object comes back in a reply,
/// and outlives its maker (spec 7.5). A provider, a child, makes an
/// object, which its quota pays for by its parts, fills it with a
/// pattern and answers init's request with a copy of its handle with
/// MAP_READ and TRANSFER alone, and ends. Then init maps the object R and
/// reads the pattern, and RW fails with ACCESS_DENIED alone. While init
/// holds the object, the memory init gave the provider is not all back;
/// once it closes the handle, it is.
fn memory_object_comes_back_in_a_reply() -> Outcome {
    const N: u16 = Call::MemMap.number();
    const SEED: u64 = 0x5EED_0000_0000;
    let before = counts_at_rest()?;
    let (reply, state) = served(Role::Provider, [child::SHARED_PAGES as u64, SEED], &[])?;
    let m = Handle::<Memory>::from_raw(abi::Handle(reply[2]));
    let args = [
        init::PROCESS.raw().0,
        m.raw().0,
        0,
        SHARED_LEN,
        WINDOW as u64,
        Access::ReadWrite.raw(),
    ];
    let refused = x0_alone::<N>(&args, Error::AccessDenied.code());
    let seen = map(&m, 0, SHARED_LEN, WINDOW, Access::Read).and_then(|()| {
        // SAFETY: the window is init's mapping of the object, readable.
        let words = (0..SHARED_LEN as usize / 8)
            .all(|i| unsafe { (WINDOW as *const u64).add(i).read_volatile() } == SEED + i as u64);
        unmap(WINDOW, SHARED_LEN).map(|()| words)
    });
    let held = counts_at_rest()?;
    close(m)?;
    let after = counts_at_rest()?;
    let rights = Rights::MAP_READ | Rights::TRANSFER;
    check(
        state == ProcessState::Exited { code: 0 }
            && reply[1] == 1
            && reply[3] == abi::msgbuf::info(abi::ObjectKind::Memory, rights),
        "the provider's reply did not bring its object with MAP_READ and TRANSFER",
    )?;
    check(
        reply[4] == PROVIDER_QUOTA - 3 * PAGE as u64,
        "the provider did not pay for its object, the node of its list and a page of its pool",
    )?;
    check(
        seen == Ok(true) && refused,
        "init did not read the pattern of the provider that ended, or mapped it RW",
    )?;
    check(
        held.0 > before.0 && after == before,
        "the memory of the provider came back before its object went, or not at all",
    )
}

/// Spec 15.2 (messages), 5.2, 7.4: a memory object's handle that moves
/// with MAP_READ and TRANSFER alone maps R only (spec 6.2): at the service
/// that gets it, mem_map RW and RX and mem_protect of its mapping R to RW
/// and to RX fail with ACCESS_DENIED, and R maps.
fn narrowed_memory_handle_maps_read_only() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    let sent = copy_raw(&m, Rights::MAP_READ | Rights::TRANSFER)?;
    let got = served(Role::Service, [SHARED_LEN, 0], &[sent]);
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 },
        "the service did not map the object R",
    )?;
    check(
        reply[7..11] == [Error::AccessDenied.code(); 4],
        "the service mapped the object RW or RX, or made its mapping so",
    )
}

/// Spec 15.2 (messages), 6.2: pages of a memory object in a message show
/// both sides. Init maps an object RW and writes INIT_WORD into its first
/// word, and sends a copy with MAP_READ, MAP_WRITE and TRANSFER to a
/// service, which maps it RW, finds INIT_WORD and writes CHILD_WORD into
/// the second word, which init reads through its own mapping.
fn shared_pages_show_both_sides() -> Outcome {
    let m = memory_object(child::SHARED_PAGES as u64)?;
    map(&m, 0, SHARED_LEN, WINDOW, Access::ReadWrite)?;
    let word = WINDOW as *mut u64;
    // SAFETY: the window is init's mapping of the object, read and write.
    unsafe { word.write_volatile(INIT_WORD) };
    let rights = Rights::MAP_READ | Rights::MAP_WRITE | Rights::TRANSFER;
    let got = copy_raw(&m, rights)
        .and_then(|sent| served(Role::Service, [SHARED_LEN, CHILD_WORD], &[sent]));
    // SAFETY: as above.
    let seen = unsafe { word.add(1).read_volatile() };
    unmap(WINDOW, SHARED_LEN)?;
    close(m)?;
    let (reply, state) = got?;
    check(
        state == ProcessState::Exited { code: 0 } && reply[7] == 0,
        "the service did not map the object RW",
    )?;
    check(reply[6] == INIT_WORD, "the service did not see init's word")?;
    check(seen == CHILD_WORD, "init did not see the service's word")
}
