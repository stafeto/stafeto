// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests with children loaded from the boot image (tests/child): loading,
//! faults, the end of a process and services across processes (spec 7.9,
//! 13.1, 13.3).

use crate::channels::exit_notice;
use crate::harness::*;
use crate::memory::memory_object;
use crate::messages::{raw_client, raw_reply};
use crate::timers::{expiry, timer_at};
use crate::transfers::copy_raw;

/// The tests of this module, in the order they run.
pub(crate) const TESTS: [Test; 27] = [
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
];

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
pub(crate) const START: u64 = 0x57A7;
const GRANDCHILD: u64 = 0x6C1D;
/// How long init waits for a child's request or its end.
pub(crate) const KID_WAIT_NS: u64 = 1_000_000_000;
/// The pause of init between two looks at a child that counts.
const PAUSE_NS: u64 = 1_000_000;
/// The quota of a child that owns no object (spec 7.5): the root of its
/// tables, two pages of its pool of blocks (the directory with the first
/// chunk of its table, then the table of its mappings), seven tables (one
/// of level 1; one of level 2 and one of level 3 each for the program, the
/// stack and the message buffer), the page of its pool of threads and its
/// buffer: 12 pages, and 3 more, which a mapping pays ahead for its tables
/// until it ends: the last mapping, of the page of marks, needs them.
pub(crate) const LEAF_QUOTA: u64 = 15 * PAGE as u64;
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
pub(crate) const PROVIDER_QUOTA: u64 = LEAF_QUOTA + (child::SHARED_PAGES as u64 + 2) * PAGE as u64;
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
pub(crate) const DATA_ABORT: u64 = 0x24;
const INSTRUCTION_ABORT: u64 = 0x20;
const WFX: u64 = 0x01;
const TRANSLATION: u64 = 0b0001;
const PERMISSION: u64 = 0b0011;

/// Maps the boot image at IMAGE, read-only, and a new page of marks at
/// KID_MARKS, for the tests of children with code.
pub(crate) fn prepare() -> Outcome {
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
    child::program_in(bytes).ok_or("the boot image has no child program")
}

/// The addresses of `part` of the child program.
fn part_of(part: Part) -> Result<core::ops::Range<u64>, &'static str> {
    let s = child_program()?.segments[part as usize];
    Ok(s.vaddr..s.vaddr + s.mem_size)
}

/// `counts` once the threads and the cleanup below init ran (`let_run`):
/// the objects of a child that ended go back at the level of its end
/// (spec 7.7).
pub(crate) fn counts_at_rest() -> Result<(u64, u64, u64), &'static str> {
    let_run()?;
    counts()
}

/// Mark `i` of the page children share with init.
pub(crate) fn kid_mark(i: usize) -> u64 {
    // SAFETY: `prepare` mapped the page at KID_MARKS, readable and
    // writable, for the whole run; children write it too, so each word is
    // reached as an atomic.
    unsafe { &*(KID_MARKS as *const AtomicU64).add(i) }.load(Relaxed)
}

pub(crate) fn reset_kid_marks() {
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
pub(crate) enum Gift {
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
pub(crate) struct Ear {
    pub(crate) channel: Handle<Channel>,
    pub(crate) exit: Handle<Channel>,
    pub(crate) timer: Handle<Timer>,
}

impl Ear {
    /// A new ear, and the copy of its channel with SEND, NOTIFY, TRANSFER
    /// and the label START that becomes the child's start channel.
    pub(crate) fn new() -> Result<(Ear, Handle<Channel>), &'static str> {
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
    pub(crate) fn next(&self) -> Result<Received, &'static str> {
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
    pub(crate) fn now(&self) -> Result<Received, Error> {
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
    pub(crate) fn answer(&self, role: Role, args: &[u64], handles: &[abi::Handle]) -> Outcome {
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
    pub(crate) fn ended(&self) -> Outcome {
        check(
            self.next()? == exit_notice(CHILD),
            "the child's exit notification did not come",
        )
    }

    /// Closes the handles; the channel goes before the copy that is the
    /// exit channel, so that the copy goes without CLIENT_GONE.
    pub(crate) fn close(self) -> Outcome {
        let closed = [self.timer.close(), self.channel.close(), self.exit.close()];
        check(
            closed.iter().all(Result::is_ok),
            "a handle of a child's ear did not close",
        )
    }
}

/// A child with code, its first thread, and its `Ear`.
pub(crate) struct Kid {
    pub(crate) process: Handle<Process>,
    pub(crate) thread: Handle<Thread>,
    pub(crate) ear: Ear,
}

impl Kid {
    /// The child program loaded as a child of init (spec 13.2) with
    /// `quota`, room for `limit` handles, ceiling and priority `level`, its
    /// start channel and its exit channel, and the page of marks mapped at
    /// child::MARKS through a copy with MAP_READ and MAP_WRITE
    /// (loader::map_narrowed); its thread does not run yet.
    pub(crate) fn load(quota: u64, limit: u32, level: u8) -> Result<Kid, &'static str> {
        Kid::load_under(quota, limit, level, level)
    }

    /// `load` with ceiling `ceiling` and the thread at `priority`.
    pub(crate) fn load_under(
        quota: u64,
        limit: u32,
        ceiling: u8,
        priority: u8,
    ) -> Result<Kid, &'static str> {
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

    pub(crate) fn start(&self) -> Outcome {
        sys::thread_start(&self.thread).map_err(|_| "thread_start of the child failed")
    }

    /// Waits for the child's start request and answers it with `role`,
    /// `args` and a copy of each of `gifts`.
    pub(crate) fn serve(&self, role: Role, args: &[u64], gifts: &[Gift]) -> Outcome {
        let mut given = [abi::Handle::INVALID; abi::MESSAGE_HANDLES];
        for (h, &g) in given.iter_mut().zip(gifts) {
            *h = self.gift(g)?;
        }
        self.ear.answer(role, args, &given[..gifts.len()])
    }

    pub(crate) fn gift(&self, g: Gift) -> Result<abi::Handle, &'static str> {
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
    pub(crate) fn end(&self) -> Result<ProcessState, &'static str> {
        self.ear.ended()?;
        sys::process_state(&self.process).map_err(|_| "PROCESS_STATE of the child failed")
    }

    /// Ends the child, if it lives, and closes init's handles.
    pub(crate) fn close(self) -> Outcome {
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
pub(crate) fn quota_of(role: Role) -> u64 {
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

/// A child at LEVEL with the quota of `role` that runs `role` with `args`
/// and `gifts`: why it ended. The cleanup of its end, at its level, ran
/// before this returns (`let_run`): the next test finds the cleanup queue
/// empty.
pub(crate) fn ran(role: Role, args: &[u64], gifts: &[Gift]) -> Result<ProcessState, &'static str> {
    ran_under(role, quota_of(role), LEVEL, LEVEL, args, gifts)
}

/// A child under ceiling child::CEILING, 30, makes the calls of `checked`
/// from EL0 (Role::Ceiling, spec 8, 11) against a thread and its process
/// under ceiling 63 that init made, with no code: a priority above the
/// caller's own ceiling fails with ACCESS_DENIED alone, in its place in
/// the order of the call's checks, and one at the ceiling passes it.
pub(crate) fn caller_ceiling(checked: Checked) -> Outcome {
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
