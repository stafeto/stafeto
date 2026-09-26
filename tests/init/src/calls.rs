// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the first calls of init, of threads and their scheduling, of
//! creating and killing processes and of object information (spec 7.5,
//! 8, 11, 13.3, 13.4).

use crate::channels::{exit_channel, exit_notice, heard_child, take_one, wait_exit};
use crate::harness::*;
use crate::messages::{mark_at_notice, take_token};
use crate::processes::{Kid, LEAF_QUOTA, caller_ceiling, kid_mark, reset_kid_marks};

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 31] = [
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
        "thread_info_reports_state_and_priorities",
        thread_info_reports_state_and_priorities,
    ),
    (
        "channel_info_reports_queue_slots_and_receivers",
        channel_info_reports_queue_slots_and_receivers,
    ),
    (
        "process_kill_returns_after_the_teardown",
        process_kill_returns_after_the_teardown,
    ),
    ("child_quota_comes_back", child_quota_comes_back),
    (
        "create_kill_cycles_leak_nothing",
        create_kill_cycles_leak_nothing,
    ),
    ("normal_build_costs", normal_build_costs),
];

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
pub(crate) fn written(line: &[u8]) -> bool {
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
pub(crate) const LOWER_END: u64 = 1 << 48;

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
/// alone on an error: kind 0, a kind past IRQ or with bits past its word
/// and a nonzero x2 fail with INVALID_ARGS, for handle 0 too; handle 0
/// with a good kind fails with BAD_HANDLE. The kinds of a process take a
/// process handle with any rights, and the system resource or a thread is
/// WRONG_TYPE; THREAD_STATE takes a thread, CHANNEL a channel and IRQ a
/// binding, each with any rights, and a process or the system resource is
/// WRONG_TYPE; KERNEL_STATS takes the system resource with KSTATS, and a
/// process is WRONG_TYPE, a copy without KSTATS ACCESS_DENIED. A good call
/// writes nothing past its words: PROCESS_STATE, «alive» here,
/// THREAD_STATE and CHANNEL x1-x4, PROCESS_MEMORY and PROCESS_HANDLES
/// x1-x3.
fn object_info_checks_its_arguments() -> Outcome {
    let own = copy(&init::PROCESS, Rights::NONE)?;
    let debug = copy(&init::RESOURCE, Rights::DEBUG)?;
    let thread = copy(&init::THREAD, Rights::NONE)?;
    let c = channel(QUIET)?;
    let seen = copy(&c, Rights::NONE)?;
    let result = object_info_cases(own.raw().0, debug.raw().0, thread.raw().0, seen.raw().0);
    close(own)?;
    close(debug)?;
    close(thread)?;
    close(seen)?;
    close(c)?;
    result
}

fn object_info_cases(own: u64, debug: u64, thread: u64, seen: u64) -> Outcome {
    const N: u16 = Call::ObjectInfo.number();
    let (state, memory, table, stats) = (
        abi::INFO_PROCESS_STATE,
        abi::INFO_PROCESS_MEMORY,
        abi::INFO_PROCESS_HANDLES,
        abi::INFO_KERNEL_STATS,
    );
    let (thread_state, channel_kind, irq) =
        (abi::INFO_THREAD_STATE, abi::INFO_CHANNEL, abi::INFO_IRQ);
    let resource = init::RESOURCE.raw().0;
    let kinds = [
        [own, 0, 0],
        [own, irq + 1, 0],
        [own, state | 1 << 32, 0],
        [own, state, 8],
        [0, 0, 0],
    ]
    .into_iter()
    .chain(
        [
            memory,
            table,
            stats,
            abi::INFO_MEMORY,
            thread_state,
            channel_kind,
            irq,
        ]
        .into_iter()
        .flat_map(|kind| [[own, kind, 1], [0, kind, 1]]),
    )
    .all(|args| x0_alone::<N>(&args, Error::InvalidArgs.code()));
    let handles = [
        (0, state, Error::BadHandle),
        (0, memory, Error::BadHandle),
        (0, table, Error::BadHandle),
        (0, stats, Error::BadHandle),
        (0, thread_state, Error::BadHandle),
        (0, channel_kind, Error::BadHandle),
        (0, irq, Error::BadHandle),
        (resource, state, Error::WrongType),
        (thread, state, Error::WrongType),
        (resource, memory, Error::WrongType),
        (resource, table, Error::WrongType),
        (own, stats, Error::WrongType),
        (debug, stats, Error::AccessDenied),
        (own, thread_state, Error::WrongType),
        (seen, thread_state, Error::WrongType),
        (own, channel_kind, Error::WrongType),
        (thread, channel_kind, Error::WrongType),
        (resource, irq, Error::WrongType),
        (seen, irq, Error::WrongType),
    ]
    .into_iter()
    .all(|(h, kind, error)| x0_alone::<N>(&[h, kind, 0], error.code()));
    let written = [
        (own, state, 5),
        (own, memory, 4),
        (own, table, 4),
        (thread, thread_state, 5),
        (seen, channel_kind, 5),
    ]
    .map(|(h, kind, past)| {
        let mut x = marked();
        x[..3].copy_from_slice(&[h, kind, 0]);
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

/// What THREAD_STATE says of the thread `t`.
fn thread_info(t: &Handle<Thread>) -> Result<ThreadInfo, Error> {
    sys::thread_info(t)
}

/// A thread with `state`, `base` and effective `priority`, FIFO.
fn fifo(state: ThreadState, base: u8, priority: u8) -> Result<ThreadInfo, Error> {
    Ok(ThreadInfo {
        state,
        base,
        priority,
        policy: Some(Policy::Fifo),
    })
}

/// Spec 8, 6.6, 11: THREAD_STATE of a thread, through a handle with no
/// rights, says what it does and at which priorities. Init runs FIFO at
/// TEST_PRIORITY; a new thread at LOW, round robin, is stopped, then
/// ready behind init, then ended. A thread at LOW waits in receive; a
/// notification of priority NOTICE wakes it at NOTICE, above init, and it
/// waits in send at once, still boosted, then for the reply once init
/// took its request, and ends with the reply.
fn thread_info_reports_state_and_priorities() -> Outcome {
    reset_results();
    let own = thread_info(&init::THREAD);
    let t = thread(1, add_mark, 1, LOW, Policy::RoundRobin)?;
    let seen = copy(&t, Rights::NONE)?;
    let stopped = thread_info(&seen);
    sys::thread_start(&t).map_err(|_| "thread_start failed")?;
    let ready = thread_info(&seen);
    let c = channel(NOTICE)?;
    let d = channel(QUIET)?;
    HANDLES[0].store(c.raw().0, Relaxed);
    HANDLES[1].store(d.raw().0, Relaxed);
    let w = spawn(0, wake_then_send, 0, LOW, Policy::Fifo)?;
    let_run()?;
    let ended = thread_info(&seen);
    let receiving = thread_info(&w);
    let posted = sys::notify(&c, 1);
    let sending = thread_info(&w);
    let token = take_token(&d);
    let awaiting = thread_info(&w);
    let replied = token.map(|t| t.reply(&[]));
    let gone = thread_info(&w).map(|i| i.state);
    let_run()?;
    for h in [w, seen, t] {
        close(h)?;
    }
    close(d)?;
    close(c)?;
    check(
        own == fifo(ThreadState::Running, TEST_PRIORITY, TEST_PRIORITY),
        "init is not running FIFO at its priority",
    )?;
    let round = |state| {
        Ok(ThreadInfo {
            state,
            base: LOW,
            priority: LOW,
            policy: Some(Policy::RoundRobin),
        })
    };
    check(
        stopped == round(ThreadState::Stopped)
            && ready == round(ThreadState::Ready)
            && ended == round(ThreadState::Ended),
        "a new thread was not stopped, then ready, then ended",
    )?;
    check(
        receiving == fifo(ThreadState::Receiving, LOW, LOW),
        "a thread waiting in receive was not seen so",
    )?;
    check(
        posted.is_ok() && sending == fifo(ThreadState::Sending, LOW, NOTICE),
        "a thread woken at NOTICE was not seen in send at its boost",
    )?;
    check(
        awaiting == fifo(ThreadState::AwaitingReply, LOW, NOTICE),
        "a thread whose request was taken did not await its reply",
    )?;
    check(
        replied == Ok(Ok(())) && gone == Ok(ThreadState::Ended),
        "the thread did not end with its reply",
    )
}

/// Waits in receive on the channel HANDLES holds for slot 0, then sends
/// request(0) through the one it holds for slot 1, and ends with the reply.
extern "C" fn wake_then_send(_: u64) -> ! {
    let _ = sys::receive(&handle(0));
    let _ = sys::send(&handle(1), &request(0));
    sys::thread_exit()
}

/// What CHANNEL says of a channel with `queued`, `receivers` and
/// `sources`, open.
fn open_channel(queued: u64, receivers: u64, sources: u64) -> Result<ChannelInfo, Error> {
    Ok(ChannelInfo {
        queued,
        receivers,
        sources,
        closed: false,
    })
}

/// Spec 6.3, 6.5, 11: CHANNEL of a channel, through its handle and
/// through a labelled copy with no rights, counts the slots in its queue,
/// merged posts once, the receivers that wait there, and its sources, the
/// slot of label 0 among them; once its last handle with RECEIVE went,
/// it is closed and its receivers woke.
fn channel_info_reports_queue_slots_and_receivers() -> Outcome {
    reset_marks();
    reset_results();
    let c = channel(QUIET)?;
    let fresh = sys::channel_info(&c);
    let one = session(&c, Rights::NOTIFY, 1, QUIET)?;
    let two = session(&c, Rights::NOTIFY, 2, QUIET)?;
    let seen = session(&c, Rights::NONE, 3, QUIET)?;
    let posted = [
        sys::notify(&c, 1),
        sys::notify(&one, 1),
        sys::notify(&two, 1),
        sys::notify(&c, 2),
    ];
    let queued = (sys::channel_info(&c), sys::channel_info(&seen));
    let taken = [0; 3].map(|_| sys::try_receive(&c).is_ok());
    let empty = sys::try_receive(&c) == Err(Error::WouldBlock);
    HANDLES[0].store(c.raw().0, Relaxed);
    let r = [
        spawn(0, mark_at_notice, 0, HIGH, Policy::Fifo)?,
        spawn(1, mark_at_notice, 0, HIGH, Policy::Fifo)?,
    ];
    let waiting = sys::channel_info(&seen);
    let woke = sys::notify(&c, 1).map(|()| mark(1));
    let left = sys::channel_info(&seen);
    close(c)?;
    let closed = sys::channel_info(&seen);
    let_run()?;
    for h in r {
        close(h)?;
    }
    for h in [seen, two, one] {
        close(h)?;
    }
    check(
        fresh == open_channel(0, 0, 1),
        "a new channel is not empty with one source",
    )?;
    check(
        posted.iter().all(Result::is_ok)
            && queued == (open_channel(3, 0, 4), open_channel(3, 0, 4)),
        "three slots, one merged twice, and four sources were not counted alike through both handles",
    )?;
    check(taken == [true; 3] && empty, "the three slots did not come")?;
    check(
        waiting == open_channel(0, 2, 4),
        "two waiting receivers were not counted",
    )?;
    check(
        woke == Ok(1) && left == open_channel(0, 1, 4),
        "a woken receiver was still counted",
    )?;
    check(
        closed
            == Ok(ChannelInfo {
                queued: 0,
                receivers: 0,
                sources: 4,
                closed: true,
            }),
        "the closed channel is not closed with no receiver",
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

/// Rounds of each measurement of `normal_build_costs`.
const COST_ROUNDS: usize = 1000;
/// The bytes of the requests and replies of `normal_build_costs`.
const COST_BYTES: [u8; 8] = *b"measured";

/// Spec 15.3: what the calls of the kernel that ships cost, the least
/// counter ticks of COST_ROUNDS rounds with the least of an empty round
/// taken off: the call with number 0, which no call has (null),
/// clock_now, yield with no other thread at init's level, notify and
/// try_receive on a channel of init, and a round trip of send and reply
/// with 8 bytes to a thread of init's own process above init. Under
/// -icount, where a tick is an instruction, it prints them on one line
/// for xtask; elsewhere the numbers mean little and it prints nothing.
/// It fails only when a call fails, never on a number.
fn normal_build_costs() -> Outcome {
    let c = channel(QUIET)?;
    let s = channel(QUIET)?;
    let t = spawn(0, echo_until_empty, s.raw().0, HIGH, Policy::Fifo)?;
    let costs = costs(&c, &s);
    let stopped = sys::send(&s, &[]).is_ok();
    close(t)?;
    close(s)?;
    close(c)?;
    let [null, clock, yielded, notify, round_trip] = costs?;
    check(stopped, "the thread that replies did not stop")?;
    if under_icount() {
        println!(
            "normal build ticks: null={null} clock={clock} yield={yielded} notify={notify} round_trip={round_trip}"
        );
    }
    Ok(())
}

/// The rows of `normal_build_costs`, in the order of its line.
fn costs(c: &Handle<Channel>, s: &Handle<Channel>) -> Result<[u64; 5], &'static str> {
    let empty = least(&mut || true)?;
    let rows = [
        least(&mut || {
            // SAFETY: no call has number 0; the kernel changes x0 alone.
            let after = unsafe { sys::raw::<0>([0; 10]) };
            after[0] == Error::InvalidArgs.code()
        }),
        least(&mut || sys::clock_now().is_ok()),
        least(&mut || sys::yield_now().is_ok()),
        least(&mut || {
            sys::notify(c, 1).is_ok()
                && matches!(sys::try_receive(c), Ok(Received::Notification { .. }))
        }),
        least(&mut || sys::send(s, &COST_BYTES).is_ok()),
    ];
    let mut costs = [0; 5];
    for (cost, row) in costs.iter_mut().zip(rows) {
        *cost = row?.saturating_sub(empty);
    }
    Ok(costs)
}

/// The least counter ticks of COST_ROUNDS rounds of `round`, which says
/// whether its calls did as they must.
fn least(round: &mut dyn FnMut() -> bool) -> Result<u64, &'static str> {
    let mut least = u64::MAX;
    for _ in 0..COST_ROUNDS {
        let start = time::now();
        let ok = round();
        let took = time::now() - start;
        check(ok, "a call of the measured rounds failed")?;
        least = least.min(took);
    }
    Ok(least)
}

/// Replies to each request on channel `h` with its bytes, until a request
/// with none, and ends.
extern "C" fn echo_until_empty(h: u64) -> ! {
    let c = Handle::<Channel>::from_raw(abi::Handle(h));
    while let Ok(Received::Message { token, len, .. }) = sys::receive(&c) {
        let replied = token.reply(&COST_BYTES[..len.min(COST_BYTES.len())]);
        if len == 0 || replied.is_err() {
            break;
        }
    }
    sys::thread_exit()
}
