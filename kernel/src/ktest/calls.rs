// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests of the system calls (spec 11, 12) for what a program does
//! not see or cannot reach: a caller whose table is full or whose quota is
//! spent, who pays for what, and the kernel's own state after a call. The
//! contract of the calls, the order of their checks, their rights and that
//! on an error only x0 changes, is the test init's (tests/init), which
//! makes the calls from EL0 on the kernel that ships. The kernel makes each
//! call here for a thread that never runs, as if the thread had made it,
//! and checks every register the call may write.
//!
//! Names tell the two sides apart: `<call>_checks_its_arguments` is the
//! test init's, one contract test per call (spec 11, 12); the kernel keeps
//! `<call>_checks_the_callers_limits` for what a caller at EL0 cannot
//! reach: a full table; a spent quota; who pays; and counts of live
//! objects. A caller whose own ceiling is below 63 is a child with code of
//! the test init (spec 15.2).

use super::{
    CAUSE, CHILD_QUOTA, PAGE, QUOTA, check, nothing_pending, read_user, registers, translates,
    wait_for_timer,
};
use crate::arch::{self, gic, timer};
use crate::boot::Boot;
use crate::channel::{self, Channel};
use crate::cleanup;
use crate::irq::{self, Irq};
use crate::memory::{self, Memory};
use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process::{self, Process, Stage};
use crate::session::{self, Session};
use crate::thread::{self, Long, THREADS, Thread};
use crate::timer::{self as timers, Timer};
use crate::{sched, syscall};
use abi::{
    Access, CHANNEL_RIGHTS, CLIENT_GONE, Call, Error, Handle, INFO_IRQ, INFO_KERNEL_STATS,
    INFO_PROCESS_HANDLES, INFO_PROCESS_MEMORY, INIT_RESOURCE_RIGHTS, IrqInfo, KernelStats,
    MAX_SLOTS, MEMORY_RIGHTS, MemoryInfo, NO_WAIT, Notification, OWNER_RIGHTS, Policy,
    ProcessHandles, ProcessMemory, ProcessState, Rights, START_CHANNEL, Source, TRIGGER_EDGE,
};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::handles::CHUNK;
use kcore::layout::{GIB, LINEAR_BASE};
use kcore::paging::{Attrs, page_descriptor};
use kcore::sched::State;
use kcore::sync::Lock;
use kcore::token::MAX_COUNT;

const LIMIT: u32 = 16;
const CEILING: u8 = 63;
const USER_VA: usize = 0x40_0000;
/// Where the message buffers of new threads go.
const BUFFER: u64 = 0x100_0000;
const FIFO: u64 = Policy::Fifo as u64;

/// A process with a thread that never runs; the kernel makes calls for it.
struct Caller {
    process: NonNull<Process>,
    thread: NonNull<Thread>,
}

impl Caller {
    fn new() -> Result<Caller, &'static str> {
        Caller::with_ceiling(CEILING)
    }

    /// A caller whose process has priority ceiling `ceiling`; its thread
    /// is FIFO at 10.
    fn with_ceiling(ceiling: u8) -> Result<Caller, &'static str> {
        Caller::with_limit(LIMIT, ceiling)
    }

    /// A caller whose process has a table of `limit` handles and priority
    /// ceiling `ceiling`; its thread is FIFO at 10.
    fn with_limit(limit: u32, ceiling: u8) -> Result<Caller, &'static str> {
        let process = process::create_root(QUOTA, limit, ceiling).map_err(|_| "no process")?;
        match thread::create(process, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
            Ok(thread) => Ok(Caller { process, thread }),
            Err(_) => {
                // SAFETY: the process is the test's, and nothing uses it afterwards.
                unsafe { process::release(process, CAUSE) };
                cleanup::drain();
                Err("no thread")
            }
        }
    }

    /// Drops the test's references; the thread and the process go unless
    /// a handle still holds them, and the cleanup queue runs dry.
    fn release(self) {
        // SAFETY: the references are the test's, and nothing uses them afterwards.
        unsafe {
            thread::release(self.thread, CAUSE);
            process::release(self.process, CAUSE);
        }
        cleanup::drain();
    }

    fn insert(&self, object: Object, rights: Rights) -> Result<Handle, &'static str> {
        process::insert_handle(self.process, object, rights).map_err(|_| "a handle did not go in")
    }

    fn close(&self, h: Handle) -> Result<(), &'static str> {
        process::close_handle(self.process, h, CAUSE).map_err(|_| "a handle did not close")
    }

    /// Makes call `number` with `args` in x0 and up, the rest of x0-x9
    /// holding marks; returns x0-x9 afterwards.
    fn call(&self, number: u16, args: &[u64]) -> [u64; 10] {
        let mut t = self.thread;
        // SAFETY: the thread is the test's and never runs.
        unsafe { t.as_mut() }.regs.x[..10].copy_from_slice(&with_marks(args));
        syscall::dispatch(t, number);
        let mut after = [0; 10];
        // SAFETY: as above.
        after.copy_from_slice(&unsafe { t.as_ref() }.regs.x[..10]);
        after
    }

    /// The next entry of a call that started over at its `svc`
    /// (syscall::restart): ELR goes past the `svc` again, as the entry from
    /// EL0 sets it, and the call runs on the registers it left; returns
    /// x0-x9 afterwards.
    fn again(&self, number: u16) -> [u64; 10] {
        let mut t = self.thread;
        // SAFETY: the thread is the test's and never runs.
        unsafe { t.as_mut() }.regs.elr += 4;
        syscall::dispatch(t, number);
        let mut after = [0; 10];
        // SAFETY: as above.
        after.copy_from_slice(&unsafe { t.as_ref() }.regs.x[..10]);
        after
    }

    /// The call fails with `error` and changes x0 alone.
    fn fails(&self, number: u16, args: &[u64], error: Error) -> Result<(), &'static str> {
        let mut want = with_marks(args);
        want[0] = error.code();
        self.expect(number, args, want)
    }

    /// The call succeeds with `values` in x1 and up and changes nothing else.
    fn succeeds(&self, number: u16, args: &[u64], values: &[u64]) -> Result<(), &'static str> {
        let mut want = with_marks(args);
        want[0] = 0;
        want[1..=values.len()].copy_from_slice(values);
        self.expect(number, args, want)
    }

    /// The call succeeds with a new handle in x1 and changes nothing else.
    fn created(&self, number: u16, args: &[u64]) -> Result<Handle, &'static str> {
        let got = self.call(number, args);
        let mut want = with_marks(args);
        want[0] = 0;
        want[1] = got[1];
        if got == want && got[1] != 0 {
            return Ok(Handle(got[1]));
        }
        kprintln!("call {number} with {args:x?}: x0-x9 are {got:x?}");
        Err("a call that makes an object failed")
    }

    fn expect(&self, number: u16, args: &[u64], want: [u64; 10]) -> Result<(), &'static str> {
        let got = self.call(number, args);
        if got == want {
            return Ok(());
        }
        kprintln!("call {number} with {args:x?}: x0-x9 are {got:x?}, expected {want:x?}");
        Err("a system call returned other registers")
    }
}

/// `args` followed by marks up to x9: a register the call must not write
/// keeps its mark.
fn with_marks(args: &[u64]) -> [u64; 10] {
    let mut x: [u64; 10] = core::array::from_fn(|i| 0x5A5A_0000_0000_0000 | i as u64);
    x[..args.len()].copy_from_slice(args);
    x
}

/// Runs `body` with a fresh caller and releases the caller afterwards.
fn with_caller<T>(
    body: impl FnOnce(&Caller) -> Result<T, &'static str>,
) -> Result<T, &'static str> {
    let caller = Caller::new()?;
    let result = body(&caller);
    caller.release();
    result
}

/// object_info reports what the kernel counts (spec 11, 16): PROCESS_MEMORY
/// the quota of the caller's process as its account holds it,
/// PROCESS_HANDLES its table, KERNEL_STATS in x1-x8 the counters of the
/// scheduler, the cleanup queue, the frame allocator, the pools and the
/// timers, each in its word. The order of the checks is the test init's
/// (object_info_checks_its_arguments).
pub fn object_info_reports_what_the_kernel_counts(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), Rights::NONE)?;
        let stats = c.insert(Object::Resource, Rights::KSTATS)?;
        let result = counted_cases(c, [own, stats]);
        c.close(own)?;
        result
    })
}

fn counted_cases(c: &Caller, handles: [Handle; 2]) -> Result<(), &'static str> {
    let [own, stats] = handles.map(|h| h.0);
    let n = Call::ObjectInfo.number();
    let (memory, table, kernel) = (INFO_PROCESS_MEMORY, INFO_PROCESS_HANDLES, INFO_KERNEL_STATS);
    let q = process::quota(c.process);
    let quota = ProcessMemory {
        quota: q.limit(),
        used: q.used(),
        returned: q.returned(),
    };
    check(
        quota.quota == QUOTA && quota.used > 0 && quota.returned == 0,
        "the caller's quota is not what it was given, or nothing is charged to it",
    )?;
    c.succeeds(n, &[own, memory, 0], &quota.to_words())?;
    let table_now = ProcessHandles {
        live: 2,
        retired: 0,
        limit: LIMIT.into(),
    };
    c.succeeds(n, &[own, table, 0], &table_now.to_words())?;
    cleanup::drain();
    let s = sched::stats();
    let counted = KernelStats {
        idle: s.idle,
        idle_latency: s.idle_latency,
        irq_latency: s.irq_latency,
        cleanup_queue: 0,
        longest_portion: cleanup::longest(),
        free_frames: phys::free_frames(),
        pool_pages: pages::taken() as u64,
        longest_firing: crate::timer::longest_firing(),
    };
    check(
        counted.longest_portion > 0 && counted.free_frames > 0 && counted.pool_pages > 0,
        "the kernel counted no portion, frame or pool page",
    )?;
    c.succeeds(n, &[stats, kernel, 0], &counted.to_words())
}

/// A handle holds its object: the last close queues a thread and a
/// process for cleanup at the level of the caller, 10, and their portions
/// let them go back to their pools; a closed handle is bad from then on.
pub fn closing_a_handle_releases_its_object(_: &Boot) -> Result<(), &'static str> {
    let (processes, threads) = (process::in_use(), thread::in_use());
    with_caller(|c| {
        let other = process::create_root(QUOTA, LIMIT, CEILING).map_err(|_| "no second process")?;
        let t = match thread::create(other, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
            Ok(t) => t,
            Err(_) => {
                // SAFETY: the process is the test's, and nothing uses it afterwards.
                unsafe { process::release(other, CAUSE) };
                return Err("no second thread");
            }
        };
        let handles = (
            c.insert(Object::Process(other), OWNER_RIGHTS),
            c.insert(Object::Thread(t), OWNER_RIGHTS),
        );
        // SAFETY: the test's references go; the handles, if any, hold the
        // objects from here on.
        unsafe {
            thread::release(t, CAUSE);
            process::release(other, CAUSE);
        }
        let (Ok(hp), Ok(ht)) = handles else {
            return Err("a handle did not go in");
        };
        close_cases(c, hp, ht, processes, threads)
    })?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the test's processes or threads stayed in their pools",
    )
}

fn close_cases(
    c: &Caller,
    hp: Handle,
    ht: Handle,
    processes: usize,
    threads: usize,
) -> Result<(), &'static str> {
    let n = Call::HandleClose.number();
    check(
        process::in_use() == processes + 2 && thread::in_use() == threads + 2,
        "a handle does not hold its object",
    )?;
    c.succeeds(n, &[ht.0], &[])?;
    check(
        thread::in_use() == threads + 2 && (cleanup::len(), cleanup::top()) == (1, Some(10)),
        "the last handle to a thread closed, and the thread was not queued at the caller's level",
    )?;
    cleanup::drain();
    check(
        thread::in_use() == threads + 1,
        "the last handle to a thread closed, and the thread stayed",
    )?;
    c.fails(n, &[ht.0], Error::BadHandle)?;
    c.succeeds(n, &[hp.0], &[])?;
    check(
        process::in_use() == processes + 2 && cleanup::len() == 1,
        "the last handle to a process closed, and the process was not queued",
    )?;
    cleanup::drain();
    check(
        process::in_use() == processes + 1,
        "the last handle to a process closed, and the process stayed",
    )?;
    c.fails(n, &[hp.0], Error::BadHandle)?;
    c.fails(n, &[0], Error::BadHandle)?;
    let resource = c.insert(Object::Resource, INIT_RESOURCE_RIGHTS)?;
    c.succeeds(n, &[resource.0], &[])?;
    c.fails(n, &[resource.0], Error::BadHandle)
}

/// thread_set_priority on a stopped thread only takes the new values
/// (spec 8, 11): its base and effective priority and its policy change,
/// and it stays stopped. The thread's process has ceiling 20. The checks
/// of the call are the test init's
/// (thread_set_priority_checks_its_arguments).
pub fn stopped_thread_takes_its_new_priority(_: &Boot) -> Result<(), &'static str> {
    let callers = [63, 20].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(c), Ok(low)] => set_priority_handles(c, low),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result
}

fn set_priority_handles(c: &Caller, low: &Caller) -> Result<(), &'static str> {
    let h = c.insert(Object::Thread(low.thread), Rights::MANAGE)?;
    set_priority_cases(c, low.thread, h)
}

fn set_priority_cases(c: &Caller, low: NonNull<Thread>, h: Handle) -> Result<(), &'static str> {
    let n = Call::ThreadSetPriority.number();
    let rr = Policy::RoundRobin as u64;
    c.succeeds(n, &[h.0, 20, rr], &[])?;
    // SAFETY: the thread is the test's and never runs.
    let t = unsafe { low.as_ref() };
    check(
        t.sched.base() == 20
            && t.sched.priority() == 20
            && t.sched.policy() == Policy::RoundRobin
            && t.sched.state() == State::Stopped,
        "a stopped thread did not take its new priority and policy",
    )
}

/// process_create stops at the caller's limits (spec 7.5, 11): with the
/// caller's table full the call fails with LIMIT_REACHED, and the new
/// process goes again. A good call returns a handle with the owner's
/// rights to a live process with the ceiling given, a child of the
/// caller's process (spec 4). Channels in x3 and x5 have cases of their
/// own (`exit_and_start_cases`). The rest of the call's checks, the
/// caller's own ceiling among them, are the test init's
/// (process_create_checks_its_arguments and its neighbours).
pub fn process_create_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let processes = process::in_use();
    let c = Caller::new()?;
    let result = process_create_cases(&c).and_then(|()| exit_and_start_cases(&c));
    c.release();
    result?;
    check(
        process::in_use() == processes,
        "a process of the test stayed in its pool",
    )
}

fn process_create_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::ProcessCreate.number();
    // The caller's table has its page of blocks from here on.
    let first = c.insert(Object::Resource, Rights::NONE)?;
    c.close(first)?;
    quota_cases(c, n)?;
    let child = c.created(n, &[CHILD_QUOTA, 16, 30, 0, 0, 0])?;
    // SAFETY: the caller's process is the test's.
    let found = unsafe { c.process.as_ref() }.lookup(child, OWNER_RIGHTS, Object::process);
    // SAFETY: the handle holds the child.
    let good = found.is_ok_and(|p| unsafe {
        p != c.process
            && p.as_ref().ceiling() == 30
            && p.as_ref().state() == ProcessState::Alive
            && process::parent(p) == Some(c.process)
    });
    c.close(child)?;
    check(
        good,
        "the handle does not name a live child of the caller with the owner's rights and its ceiling",
    )?;
    full_table_cases(c, n)
}

/// The child's quota comes off the caller's (spec 7.5): more than is left
/// there is NO_MEMORY. The least quota covers the
/// child's root table and the page of its pool of blocks, which holds its
/// directory and the chunk with entry 0: 8 KiB. A page is NO_MEMORY at
/// entry 0, and the caller gets the quota back whole; the page of its pool
/// of shells, which the child took, stays the caller's (spec 7.8). A
/// thread does not fit in the least child: NO_MEMORY, and what the call
/// took goes back.
fn quota_cases(c: &Caller, n: u16) -> Result<(), &'static str> {
    let page = PAGE_SIZE;
    let q = process::quota(c.process);
    let over = (q.limit() - q.returned() - q.used() + 1).next_multiple_of(page);
    c.fails(n, &[over, 16, 30, 0, 0, 0], Error::NoMemory)?;
    let before = q.used();
    c.fails(n, &[page, 16, 30, 0, 0, 0], Error::NoMemory)?;
    cleanup::drain();
    check(
        process::quota(c.process).used() == before + page,
        "a child that was not made kept the caller's quota beyond the page of its shells",
    )?;
    let least = c.created(n, &[2 * page, 16, 30, 0, 0, 0])?;
    let result = full_child_cases(c, least).and_then(|()| full_table_thread_quota_cases(c, least));
    c.close(least)?;
    cleanup::drain();
    result?;
    check(
        process::quota(c.process).used() == before + page,
        "the least child's quota did not come back",
    )
}

/// Channels in x3 and x5 of process_create, for what a program cannot see
/// (spec 11, 13.3): the caller's full table comes before the channel's
/// slots and the quota (LIMIT_REACHED), and a good call moves x5 into
/// entry 0 of the child's table with its rights, and the caller's handle
/// goes. The test init checks the rest from EL0.
fn exit_and_start_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::ProcessCreate.number();
    let q = CHILD_QUOTA;
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let result = with_full_table(c, n, &[q, 16, 20, h.0, 5, 0])
        .and_then(|()| channel_of(c, h))
        .and_then(|ch| moved_start(c, h, ch));
    c.close(h)?;
    cleanup::drain();
    result
}

/// x5 moves: a copy with NOTIFY and TRANSFER goes into entry 0 of the
/// child's table with those rights, and the caller's handle is bad.
fn moved_start(c: &Caller, h: Handle, ch: NonNull<Channel>) -> Result<(), &'static str> {
    let rights = Rights::NOTIFY | Rights::TRANSFER;
    let start = c.insert(Object::Channel(ch), rights)?;
    let n = Call::ProcessCreate.number();
    let child = c.created(n, &[CHILD_QUOTA, 16, 20, h.0, 5, start.0])?;
    // SAFETY: the caller's process is the test's.
    let table = unsafe { c.process.as_ref() };
    let gone = table.lookup(start, Rights::NONE, Object::channel);
    let entry = child_of(c, child).map(|p| {
        // SAFETY: the caller's handle holds the child.
        unsafe { p.as_ref() }.lookup_with_rights(START_CHANNEL, Rights::NONE, Object::channel)
    });
    c.close(child)?;
    cleanup::drain();
    check(
        gone == Err(Error::BadHandle) && entry == Ok(Ok((ch, rights))),
        "the caller kept x5, or entry 0 of the child does not name it with its rights",
    )
}

/// thread_create in `child`, whose quota its own objects take up: its
/// thread's buffer does not fit, NO_MEMORY, and the thread goes again.
fn full_child_cases(c: &Caller, child: Handle) -> Result<(), &'static str> {
    // SAFETY: the caller's process is the test's.
    let p = unsafe { c.process.as_ref() }
        .lookup(child, Rights::NONE, Object::process)
        .map_err(|_| "the handle does not name the child")?;
    let used = process::quota(p).used();
    let args = thread_args(child.0, USER_VA as u64, USER_VA as u64, 10, FIFO, BUFFER);
    c.fails(Call::ThreadCreate.number(), &args, Error::NoMemory)?;
    cleanup::drain();
    check(
        process::quota(p).used() == used,
        "a thread that did not fit kept the child's quota",
    )
}

/// thread_create into `child`, whose quota has no room for the thread
/// either, with the caller's table full too: LIMIT_REACHED, checked before
/// the quota (spec 11), even though the quota alone already fails the
/// call (`full_child_cases`).
fn full_table_thread_quota_cases(c: &Caller, child: Handle) -> Result<(), &'static str> {
    let n = Call::ThreadCreate.number();
    let args = thread_args(child.0, USER_VA as u64, USER_VA as u64, 10, FIFO, BUFFER);
    with_full_table(c, n, &args)
}

/// Every process pays for the directory and chunks of its own table,
/// whoever puts the handle there (spec 7.5, 7.8): process_create charges
/// the caller the child's quota and the page of its pool of shells, and
/// the child pays from its quota for its root table and the page of its
/// pool of blocks with its directory and the chunk with entry 0. A handle
/// the kernel puts in the child's table past its first chunk takes a
/// second page of blocks, which the child pays for too. Once the child
/// goes, the caller has its quota back and keeps the page of its shells.
pub fn table_chunks_are_paid_by_the_owner(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        // The caller's table has its directory and first chunk from here on.
        let first = c.insert(Object::Resource, Rights::NONE)?;
        let before = process::quota(c.process).used();
        let n = Call::ProcessCreate.number();
        let child = c.created(n, &[CHILD_QUOTA, 2 * CHUNK as u64, 20, 0, 0, 0])?;
        let result = owner_pays(c, child, before);
        c.close(child)?;
        cleanup::drain();
        c.close(first)?;
        result?;
        check(
            process::quota(c.process).used() == before + PAGE_SIZE,
            "the child's quota did not come back whole",
        )
    })
}

fn owner_pays(c: &Caller, child: Handle, before: u64) -> Result<(), &'static str> {
    // SAFETY: the caller's process is the test's.
    let p = unsafe { c.process.as_ref() }
        .lookup(child, Rights::NONE, Object::process)
        .map_err(|_| "the handle does not name the child")?;
    let own = 2 * PAGE_SIZE;
    check(
        process::quota(c.process).used() == before + CHILD_QUOTA + PAGE_SIZE,
        "the caller paid for more than the child's quota and the page of its shells",
    )?;
    check(
        process::quota(p).used() == own,
        "the child did not pay for its root table and the page of its directory and first chunk",
    )?;
    // Entry 0 and 63 more fill the first chunk; the next takes a second.
    for _ in 0..=CHUNK {
        process::insert_handle(p, Object::Resource, Rights::NONE)
            .map_err(|_| "a handle did not go into the child")?;
    }
    check(
        process::quota(p).used() == own + PAGE_SIZE
            && process::quota(c.process).used() == before + CHILD_QUOTA + PAGE_SIZE,
        "the child's second chunk was not charged to the child",
    )
}

/// The shell of a child that process_create made lies in the caller's pool
/// of shells (spec 7.5, 7.8): the least quota, 8 KiB, pays for the child's
/// root table and its first page of blocks alone, and the caller pays one
/// page for the shells of two children. The page stays the caller's when
/// the children go.
pub fn child_shell_is_paid_by_the_parent(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let n = Call::ProcessCreate.number();
        let least = 2 * PAGE_SIZE;
        // The caller's table has its page of blocks from here on.
        let first = c.insert(Object::Resource, Rights::NONE)?;
        c.close(first)?;
        let before = process::quota(c.process).used();
        let children = [0, 1].map(|_| c.created(n, &[least, 16, 20, 0, 0, 0]));
        let result = match children {
            [Ok(a), Ok(b)] => shells_cases(c, [a, b], before),
            _ => Err("a child with the least quota was not made"),
        };
        for h in children.into_iter().flatten() {
            c.close(h)?;
        }
        cleanup::drain();
        result?;
        check(
            process::quota(c.process).used() == before + PAGE_SIZE,
            "the page of the caller's shells did not stay, or the children's quotas did",
        )
    })
}

fn shells_cases(c: &Caller, children: [Handle; 2], before: u64) -> Result<(), &'static str> {
    for h in children {
        // SAFETY: the caller's process is the test's.
        let p = unsafe { c.process.as_ref() }
            .lookup(h, Rights::NONE, Object::process)
            .map_err(|_| "the handle does not name the child")?;
        check(
            process::quota(p).used() == 2 * PAGE_SIZE,
            "a child paid for more than its root table and its first page of blocks",
        )?;
    }
    check(
        process::quota(c.process).used() == before + 2 * 2 * PAGE_SIZE + PAGE_SIZE,
        "the caller did not pay one page for the shells of its two children",
    )
}

/// A child that process_create made has a stub in entry 0 of its table
/// (spec 13.3): the first handle that goes in there gets another value,
/// and START_CHANNEL stays bad.
pub fn entry_0_of_a_child_stays_bad(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let n = Call::ProcessCreate.number();
        let child = c.created(n, &[CHILD_QUOTA, 16, 20, 0, 0, 0])?;
        let result = start_entry_cases(c, child);
        c.close(child)?;
        result
    })
}

fn start_entry_cases(c: &Caller, child: Handle) -> Result<(), &'static str> {
    // SAFETY: the caller's process is the test's.
    let p = unsafe { c.process.as_ref() }
        .lookup(child, Rights::NONE, Object::process)
        .map_err(|_| "the handle does not name the child")?;
    let first = process::insert_handle(p, Object::Resource, Rights::DEBUG)
        .map_err(|_| "a handle did not go into the child")?;
    // SAFETY: the caller's handle holds the child.
    let start = unsafe { p.as_ref() }.lookup(START_CHANNEL, Rights::NONE, Object::resource);
    check(
        first != START_CHANNEL && start == Err(Error::BadHandle),
        "START_CHANNEL names a handle of the child",
    )
}

/// A full table of the caller: LIMIT_REACHED, and the new process goes.
/// LIMIT_REACHED even when the quota would not have covered the child
/// either (spec 11): the table has no room, a limit that needs no
/// allocation, and the call checks it before it ever charges the quota.
fn full_table_cases(c: &Caller, n: u16) -> Result<(), &'static str> {
    cleanup::drain();
    let processes = process::in_use();
    with_full_table(c, n, &[CHILD_QUOTA, 16, 30, 0, 0, 0])?;
    let q = process::quota(c.process);
    let over = (q.limit() - q.returned() - q.used() + 1).next_multiple_of(PAGE_SIZE);
    with_full_table(c, n, &[over, 16, 30, 0, 0, 0])?;
    cleanup::drain();
    check(
        process::in_use() == processes,
        "the process of a call that failed stayed",
    )
}

/// Call `n` with `args` fails with LIMIT_REACHED while the caller's table
/// is full.
fn with_full_table(c: &Caller, n: u16, args: &[u64]) -> Result<(), &'static str> {
    let mut filler = [None; LIMIT as usize];
    for slot in &mut filler {
        match process::insert_handle(c.process, Object::Resource, Rights::NONE) {
            Ok(h) => *slot = Some(h),
            Err(_) => break,
        }
    }
    let result = c.fails(n, args, Error::LimitReached);
    for h in filler.into_iter().flatten() {
        c.close(h)?;
    }
    result
}

/// thread_create stops at the caller's limits (spec 8, 11): with the
/// caller's table full the call fails with LIMIT_REACHED, and the new
/// thread and its page go again. A good call makes a stopped thread whose
/// buffer is a zeroed page, readable and writable, never executable, and
/// returns a handle with the owner's rights; the page goes with the
/// thread. The target process has ceiling 20. The rest of the call's
/// checks, the caller's own ceiling among them, are the test init's
/// (thread_create_checks_its_arguments).
pub fn thread_create_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let callers = [63, 20].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(c), Ok(low)] => thread_create_handles(c, low),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result
}

fn thread_create_handles(c: &Caller, low: &Caller) -> Result<(), &'static str> {
    let h = c.insert(Object::Process(low.process), Rights::MANAGE)?;
    thread_create_cases(c, low.process, h)
}

/// thread_create's arguments: the process, entry, stack, argument 7,
/// priority, policy and buffer.
fn thread_args(
    process: u64,
    entry: u64,
    stack: u64,
    priority: u64,
    policy: u64,
    buffer: u64,
) -> [u64; 7] {
    [process, entry, stack, 7, priority, policy, buffer]
}

fn thread_create_cases(
    c: &Caller,
    low: NonNull<Process>,
    to_low: Handle,
) -> Result<(), &'static str> {
    let to_low = to_low.0;
    let n = Call::ThreadCreate.number();
    let good = |h, priority| thread_args(h, USER_VA as u64, 0x80_1000, priority, FIFO, BUFFER);
    let h = c.created(n, &good(to_low, 20))?;
    let result = new_thread_cases(c, low, h);
    c.close(h)?;
    result?;
    cleanup::drain();
    check(
        process::translate(low, BUFFER as usize).is_none(),
        "the buffer's page outlived its thread",
    )?;
    // A full table of the caller: LIMIT_REACHED, and the new thread and
    // its buffer go; the buffer's page tables stay with the process.
    let (threads, frames) = (thread::in_use(), phys::free_frames());
    with_full_table(c, n, &good(to_low, 20))?;
    cleanup::drain();
    check(
        thread::in_use() == threads
            && process::translate(low, BUFFER as usize).is_none()
            && phys::free_frames() == frames,
        "the thread of a call that failed stayed, or its buffer did",
    )
}

/// The thread behind `h` is stopped, starts as it was told, and has a
/// zeroed buffer page that EL0 reads and writes and never executes.
fn new_thread_cases(c: &Caller, low: NonNull<Process>, h: Handle) -> Result<(), &'static str> {
    // SAFETY: the caller's process is the test's.
    let t = unsafe { c.process.as_ref() }
        .lookup(h, OWNER_RIGHTS, Object::thread)
        .map_err(|_| "the handle does not name a thread with the owner's rights")?;
    // SAFETY: the handle holds the thread, which never runs.
    let t = unsafe { t.as_ref() };
    check(
        t.regs.x[0] == 7
            && t.regs.elr == USER_VA as u64
            && t.regs.sp == 0x80_1000
            && t.sched.base() == 20
            && t.sched.policy() == Policy::Fifo
            && t.sched.state() == State::Stopped
            && t.process() == low,
        "the new thread does not start as it was told",
    )?;
    let Some((pa, descriptor)) = process::translate(low, BUFFER as usize) else {
        return Err("the buffer is not mapped");
    };
    check(
        descriptor == page_descriptor(pa, Attrs::USER_DATA),
        "the buffer is not a page EL0 reads and writes and never executes",
    )?;
    // SAFETY: the frame is the thread's, reached through the linear map.
    let zero = (0..PAGE_SIZE / 8)
        .all(|i| unsafe { ((LINEAR_BASE + (pa + 8 * i) as usize) as *const u64).read() } == 0);
    check(zero, "the buffer is not zeroed")
}

/// thread_create whose quota covers the frame of the new thread's buffer
/// but no table to map it: NO_MEMORY, and the frame goes back to the
/// allocator and to the quota, with the thread (spec 7.5, 7.8, 11).
pub fn buffer_that_does_not_map_goes_back(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), OWNER_RIGHTS)?;
        let args = thread_args(own.0, USER_VA as u64, 0x80_1000, 10, FIFO, BUFFER);
        let before = (process::quota(c.process).used(), phys::free_frames());
        let result = with_quota_left(c, PAGE_SIZE, || {
            c.fails(Call::ThreadCreate.number(), &args, Error::NoMemory)
        });
        cleanup::drain();
        c.close(own)?;
        result?;
        check(
            (process::quota(c.process).used(), phys::free_frames()) == before
                && process::translate(c.process, BUFFER as usize).is_none(),
            "the frame of a buffer that did not map stayed taken",
        )
    })
}

/// process_kill ends a process whatever state its threads are in: a ready
/// thread leaves the queue, a stopped one ends where it is (spec 11), both
/// in the call. The process's space and its threads' buffers go with the
/// cleanup at the caller's level, which runs before the caller does again:
/// here the test runs the queue itself. Until then thread_create finds the
/// process ended (BAD_STATE) and makes nothing. A running thread's case is
/// the test init's `process_kills_itself`, and so are the reason and the
/// handles of the calls.
pub fn process_kill_ends_threads_in_every_state(_: &Boot) -> Result<(), &'static str> {
    let (processes, threads) = (process::in_use(), thread::in_use());
    with_caller(kill_cases)?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the test's processes or threads stayed in their pools",
    )
}

fn kill_cases(c: &Caller) -> Result<(), &'static str> {
    let child = c.created(
        Call::ProcessCreate.number(),
        &[CHILD_QUOTA, 16, 20, 0, 0, 0],
    )?;
    let make = |buffer| {
        let args = thread_args(child.0, USER_VA as u64, USER_VA as u64, 10, FIFO, buffer);
        c.created(Call::ThreadCreate.number(), &args)
    };
    let threads = [make(BUFFER), make(BUFFER + PAGE_SIZE)];
    let result = match threads {
        [Ok(ready), Ok(stopped)] => kill_objects(c, [child, ready, stopped]),
        _ => Err("no thread in the child"),
    };
    for h in threads.into_iter().flatten().chain([child]) {
        c.close(h)?;
    }
    result
}

fn kill_objects(c: &Caller, handles: [Handle; 3]) -> Result<(), &'static str> {
    let [child, ready, stopped] = handles;
    // SAFETY: the caller's process is the test's.
    let p = unsafe { c.process.as_ref() };
    let (Ok(tr), Ok(ts)) = (
        p.lookup(ready, OWNER_RIGHTS, Object::thread),
        p.lookup(stopped, OWNER_RIGHTS, Object::thread),
    ) else {
        return Err("the new handles do not name their threads");
    };
    kill_calls(c, [child, ready], [tr, ts])
}

fn kill_calls(
    c: &Caller,
    [child, ready]: [Handle; 2],
    [tr, ts]: [NonNull<Thread>; 2],
) -> Result<(), &'static str> {
    c.succeeds(Call::ThreadStart.number(), &[ready.0], &[])?;
    check(
        sched::first(10) == Some(tr),
        "a started thread is not ready",
    )?;
    let kill = Call::ProcessKill.number();
    let frames = phys::free_frames();
    c.succeeds(kill, &[child.0], &[])?;
    // SAFETY: the handles hold the threads.
    let dead = unsafe { [tr, ts].map(|t| t.as_ref().sched.state() == State::Dead) };
    check(
        dead == [true, true] && sched::first(10).is_none(),
        "a thread of the killed process did not end",
    )?;
    check(
        (cleanup::len(), cleanup::top()) == (1, Some(10)),
        "the killed process was not queued at the caller's level",
    )?;
    // Until the stage Space the space is there, and a free page for a
    // buffer too: only the end keeps a new thread and its buffer out of
    // the process.
    let buffer = BUFFER + 2 * PAGE_SIZE;
    let args = thread_args(child.0, USER_VA as u64, USER_VA as u64, 10, FIFO, buffer);
    let threads = thread::in_use();
    c.fails(Call::ThreadCreate.number(), &args, Error::BadState)?;
    check(
        thread::in_use() == threads,
        "thread_create made a thread in a process that ended",
    )?;
    cleanup::drain();
    // Four tables (levels 0-3 over both buffers) and two buffers.
    check(
        phys::free_frames() == frames + 6,
        "the killed process kept its tables or its threads' buffers",
    )
}

/// process_kill of a process that ended before hastens its teardown
/// (spec 7.7, 11): a child ended at 2 waits behind a thread ready at 10
/// of the caller's process; the kill from the caller's thread at 20 raises
/// the teardown to 20, so that the whole of it, the stage Quota included,
/// runs before the caller's thread does again, and the queue is empty
/// then. The thread at 10 is still ready.
pub fn kill_hastens_a_dying_process(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        sched::set_priority(c.thread, 20, Policy::Fifo).map_err(|_| "no priority 20")?;
        let child = c.created(
            Call::ProcessCreate.number(),
            &[CHILD_QUOTA, 16, 20, 0, 0, 0],
        )?;
        let ready = thread::create(c.process, USER_VA, USER_VA, 0, 10, Policy::Fifo)
            .map_err(|_| "no thread")?;
        let result = thread::start(ready)
            .map_err(|_| "the thread did not start")
            .and_then(|()| hasten_cases(c, child, ready));
        // SAFETY: the test's references go; the ready thread leaves the
        // scheduler first.
        unsafe {
            sched::exit(ready, CAUSE);
            thread::release(ready, CAUSE);
        }
        c.close(child)?;
        result
    })
}

fn hasten_cases(c: &Caller, child: Handle, ready: NonNull<Thread>) -> Result<(), &'static str> {
    // SAFETY: the caller's process is the test's.
    let p = unsafe { c.process.as_ref() }
        .lookup(child, Rights::NONE, Object::process)
        .map_err(|_| "the handle does not name the child")?;
    // SAFETY: the handle holds the child.
    unsafe { process::end(p, ProcessState::Killed, 2) };
    check(
        cleanup::top() == Some(2) && sched::first(10) == Some(ready),
        "the child's teardown does not wait at 2 behind the thread at 10",
    )?;
    c.succeeds(Call::ProcessKill.number(), &[child.0], &[])?;
    check(
        cleanup::top() == Some(20),
        "process_kill of a process that ended did not raise its teardown to the caller's level",
    )?;
    // What runs before the caller's thread at 20 does again.
    while cleanup::top().is_some_and(|level| level >= 20) {
        cleanup::portion();
    }
    check(
        process::progress(p).0 == process::Stage::Shell && cleanup::len() == 0,
        "the teardown did not pass its stage Quota before the caller ran again",
    )?;
    check(
        sched::first(10) == Some(ready),
        "the thread at 10 did not stay ready",
    )
}

/// x1-x9 of a receive that took `count` posts of `bits` from the slot of
/// label 0; x10 and x11, the label and the token, are 0.
fn unlabeled(bits: u64, count: u32) -> [u64; 9] {
    let n = Notification {
        source: Source::Unlabeled,
        label: 0,
        bits,
        count,
    };
    n.to_words()[..9].try_into().expect("x1-x9")
}

/// The channel behind the caller's handle `h`.
fn channel_of(c: &Caller, h: Handle) -> Result<NonNull<Channel>, &'static str> {
    // SAFETY: the caller's process is the test's.
    unsafe { c.process.as_ref() }
        .lookup(h, Rights::NONE, Object::channel)
        .map_err(|_| "the handle does not name a channel")
}

/// Runs `body` with the rest of the caller's quota charged, so that no new
/// page fits (NO_MEMORY), and gives the rest back afterwards.
fn with_used_quota(
    c: &Caller,
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    with_quota_left(c, 0, body)
}

/// Runs `body` with all but `left` bytes of the caller's quota charged,
/// and refunds the charge afterwards.
fn with_quota_left(
    c: &Caller,
    left: u64,
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    with_left(c.process, left, body)
}

/// Runs `body` with all but `left` bytes of the quota of `p` charged, and
/// refunds the charge afterwards.
fn with_left(
    p: NonNull<Process>,
    left: u64,
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let q = process::quota(p);
    let rest = q.limit() - q.returned() - q.used() - left;
    process::charge(p, rest).map_err(|_| "the rest of the quota did not charge")?;
    let result = body();
    process::refund(p, rest);
    result
}

/// channel_create stops at the caller's limits (spec 7.8, 11): with the
/// caller's table full it fails with LIMIT_REACHED, and with its quota
/// spent with NO_MEMORY for a page of its pool of channels, with nothing
/// made. A good call returns a handle with abi::CHANNEL_RIGHTS to a
/// channel the caller pays for. The rest of the checks of channel_create,
/// notify and receive, the caller's own ceiling among them, are the test
/// init's.
pub fn channel_create_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let channels = channel::in_use();
    let c = Caller::new()?;
    let result = channel_create_cases(&c);
    c.release();
    result?;
    check(
        channel::in_use() == channels,
        "a channel of the test stayed in its pool",
    )
}

fn channel_create_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::CreateChannel.number();
    // The table's first page of blocks, so that the page below is the
    // pool's.
    let resource = c.insert(Object::Resource, Rights::NONE)?;
    let channels = channel::in_use();
    with_used_quota(c, || {
        c.fails(n, &[30], Error::NoMemory)?;
        with_full_table(c, n, &[30])
    })?;
    cleanup::drain();
    check(
        channel::in_use() == channels,
        "a channel that did not fit stayed",
    )?;
    let h = c.created(n, &[30])?;
    let result = channel_of(c, h).and_then(|ch| {
        // SAFETY: the caller's process is the test's.
        let rights = unsafe { c.process.as_ref() }.lookup(h, CHANNEL_RIGHTS, Object::channel);
        check(
            rights.is_ok() && channel::payer(ch) == c.process,
            "the handle does not carry the channel's rights, or the caller does not pay",
        )
    });
    c.close(h)?;
    c.close(resource)?;
    result
}

/// (base, effective) priority of `t`, which never runs.
fn priorities(t: NonNull<Thread>) -> (u8, u8) {
    // SAFETY: the thread is the test's.
    let n = unsafe { &t.as_ref().sched };
    (n.base(), n.priority())
}

/// The boost by a notification never lifts a thread above the ceiling of
/// its process (spec 6.6, 8): a channel of priority 40, which a process
/// under ceiling 63 made, notifies a receiver at base 10 under ceiling 30,
/// which works at 30 afterwards; a receiver at base 10 under ceiling 63
/// works at 40. The next receive of each ends its boost.
pub fn boost_is_capped_by_the_ceiling(_: &Boot) -> Result<(), &'static str> {
    let callers = [63, 30].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(owner), Ok(low)] => boost_cases(owner, low),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result
}

fn boost_cases(owner: &Caller, low: &Caller) -> Result<(), &'static str> {
    let h = owner.created(Call::CreateChannel.number(), &[40])?;
    let result = channel_of(owner, h).and_then(|ch| {
        let r = low.insert(Object::Channel(ch), Rights::RECEIVE)?;
        let result = boost_levels(owner, low, h, r);
        low.close(r)?;
        result
    });
    owner.close(h)?;
    result
}

fn boost_levels(owner: &Caller, low: &Caller, h: Handle, r: Handle) -> Result<(), &'static str> {
    let (notify, receive) = (Call::Notify.number(), Call::Receive.number());
    owner.succeeds(notify, &[h.0, 1], &[])?;
    low.succeeds(receive, &[r.0, NO_WAIT], &unlabeled(1, 1))?;
    check(
        priorities(low.thread) == (10, 30),
        "the boost of a receiver under ceiling 30 is not 30",
    )?;
    owner.succeeds(notify, &[h.0, 1], &[])?;
    owner.succeeds(receive, &[h.0, NO_WAIT], &unlabeled(1, 1))?;
    check(
        priorities(owner.thread) == (10, 40),
        "the boost of a receiver under ceiling 63 is not the notification's 40",
    )?;
    low.fails(receive, &[r.0, NO_WAIT], Error::WouldBlock)?;
    owner.fails(receive, &[h.0, NO_WAIT], Error::WouldBlock)?;
    check(
        priorities(low.thread) == (10, 10) && priorities(owner.thread) == (10, 10),
        "the next receive did not end the boost",
    )
}

/// x1-x9 of a receive that took `count` posts of `bits` from the slot of
/// the session with `label`, which x10 holds (`label_of`).
fn labelled(label: u64, bits: u64, count: u32) -> [u64; 9] {
    let n = Notification {
        source: Source::Session,
        label,
        bits,
        count,
    };
    n.to_words()[..9].try_into().expect("x1-x9")
}

/// x10 of the caller's thread: the label of what its receive took.
fn label_of(c: &Caller) -> u64 {
    // SAFETY: the thread is the test's and never runs.
    unsafe { c.thread.as_ref() }.regs.x[10]
}

/// The session behind the caller's handle `h`.
fn session_of(c: &Caller, h: Handle) -> Result<NonNull<Session>, &'static str> {
    // SAFETY: the caller's process is the test's.
    unsafe { c.process.as_ref() }
        .lookup(h, Rights::NONE, Object::session)
        .map_err(|_| "the handle does not name a session")
}

/// handle_duplicate stops at the caller's limits (spec 5.3, 11), the
/// resources in the order the call takes them: the caller's table
/// (LIMIT_REACHED), the channel's slots
/// (LIMIT_REACHED, abi::MAX_SLOTS with the slot of label 0), the caller's
/// quota for a page of its pool of sessions (NO_MEMORY); nothing is made
/// then. A good call returns the copy in x1 alone: with label 0 it names
/// the same object, a session's copy the same session; a label makes a
/// session of the channel at the priority, which the caller pays for. A
/// copy with a label and RECEIVE keeps the channel open. The rest of the
/// call's checks, the caller's own ceiling among them, are the test
/// init's (handle_duplicate_checks_its_arguments and its neighbours).
pub fn handle_duplicate_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let (sessions, channels) = (session::in_use(), channel::in_use());
    let callers = [63, 63].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(c), Ok(other)] => duplicate_cases(c, other),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result?;
    check(
        session::in_use() == sessions && channel::in_use() == channels,
        "a session or a channel of the test stayed in its pool",
    )
}

fn duplicate_cases(c: &Caller, other: &Caller) -> Result<(), &'static str> {
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let result = (|| {
        let resource = c.insert(Object::Resource, Rights::DEBUG | Rights::DUPLICATE)?;
        let result = duplicate_resources(c, h)
            .and_then(|()| duplicate_results(c, [h, resource]))
            .and_then(|()| slots_come_before_the_quota(c, other));
        c.close(resource)?;
        result
    })();
    // Closed already when the cases went through.
    let _ = process::close_handle(c.process, h, super::CAUSE);
    result
}

/// The resources of a label, none of which makes a session: the caller's
/// quota falls short for the first page of its pool of sessions
/// (NO_MEMORY), and its full table comes first (LIMIT_REACHED).
fn duplicate_resources(c: &Caller, h: Handle) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let args = [h.0, u64::from(Rights::NOTIFY.0), 7, 10];
    let sessions = session::in_use();
    with_used_quota(c, || {
        c.fails(n, &args, Error::NoMemory)?;
        with_full_table(c, n, &args)
    })?;
    with_full_table(c, n, &[h.0, u64::from(Rights::NOTIFY.0), 0, 0])?;
    cleanup::drain();
    check(
        session::in_use() == sessions,
        "a session of a call that failed stayed",
    )
}

/// Good calls: copies with label 0 of the resource and of a session, a
/// session of the channel, a new label on a session (BAD_STATE), and a
/// copy with a label and RECEIVE that keeps the channel
/// open once its handle with no label went; its close closes the channel,
/// and a new label on it fails with PEER_CLOSED.
fn duplicate_results(c: &Caller, handles: [Handle; 2]) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let [h, resource] = handles;
    let (notify, receive) = (u64::from(Rights::NOTIFY.0), u64::from(Rights::RECEIVE.0));
    let debug = c.created(n, &[resource.0, u64::from(Rights::DEBUG.0), 0, 0])?;
    // SAFETY: the caller's process is the test's.
    let table = unsafe { c.process.as_ref() };
    check(
        table.lookup(debug, Rights::DEBUG, Object::resource).is_ok()
            && table.lookup(debug, Rights::DUPLICATE, Object::resource) == Err(Error::AccessDenied),
        "the copy of the resource does not carry DEBUG alone",
    )?;
    c.close(debug)?;
    let duplicate = u64::from((Rights::NOTIFY | Rights::DUPLICATE).0);
    let first = c.created(n, &[h.0, duplicate, 7, 30])?;
    let same = c.created(n, &[first.0, notify, 0, 0])?;
    let s = session_of(c, first)?;
    let named = session_of(c, same).is_ok_and(|t| t == s)
        && session::label(s) == 7
        && session::priority(s) == 30
        && Some(session::channel(s)) == channel_of(c, h).ok()
        && session::payer(s) == c.process;
    c.fails(n, &[first.0, notify, 8, 30], Error::BadState)?;
    let left = c.created(n, &[h.0, duplicate, 0, 0])?;
    let receiver = c.created(n, &[h.0, receive, 9, 10])?;
    c.close(h)?;
    c.succeeds(Call::Notify.number(), &[same.0, 1], &[])?;
    c.succeeds(
        Call::Receive.number(),
        &[receiver.0, NO_WAIT],
        &labelled(7, 1, 1),
    )?;
    let label = label_of(c);
    c.close(receiver)?;
    c.fails(n, &[left.0, notify, 8, 10], Error::PeerClosed)?;
    c.fails(Call::Notify.number(), &[same.0, 1], Error::PeerClosed)?;
    for handle in [first, same, left] {
        c.close(handle)?;
    }
    cleanup::drain();
    check(
        named,
        "the session does not carry the label, the priority, the channel and the caller as its payer",
    )?;
    check(
        label == 7,
        "a copy with a label and RECEIVE did not keep the channel open",
    )
}

/// The channel's slots come before the quota: `other` fills the slots of
/// the channel with sessions it closes at once, CLIENT_GONE holding each,
/// until LIMIT_REACHED; then a label fails with LIMIT_REACHED even with
/// the caller's quota used up. The channel is a new one: the first closed.
fn slots_come_before_the_quota(c: &Caller, other: &Caller) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let result = channel_of(c, h).and_then(|ch| {
        let d = other.insert(Object::Channel(ch), Rights::DUPLICATE)?;
        let mut made = 0;
        let full = loop {
            let got = other.call(n, &[d.0, 0, made + 1, 10]);
            if got[0] != 0 {
                break got[0];
            }
            other.close(Handle(got[1]))?;
            made += 1;
        };
        other.close(d)?;
        check(
            full == Error::LimitReached.code() && made == u64::from(MAX_SLOTS) - 1,
            "the slots of a channel did not end at abi::MAX_SLOTS with the slot of label 0",
        )?;
        with_used_quota(c, || {
            c.fails(
                n,
                &[h.0, u64::from(Rights::NOTIFY.0), 1, 10],
                Error::LimitReached,
            )
        })
    });
    c.close(h)?;
    cleanup::drain();
    result
}

/// A session lies in the pool of the process that called handle_duplicate,
/// which pays for its page (spec 5.3, 7.8): the owner makes a channel, a
/// client with a copy with DUPLICATE labels it twice; the client's used
/// memory grows by one page, and the owner's does not change.
pub fn session_is_paid_by_the_caller(_: &Boot) -> Result<(), &'static str> {
    let sessions = session::in_use();
    let callers = [63, 63].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(owner), Ok(client)] => paid_sessions(owner, client),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result?;
    check(
        session::in_use() == sessions,
        "a session of the test stayed in its pool",
    )
}

fn paid_sessions(owner: &Caller, client: &Caller) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let h = owner.created(Call::CreateChannel.number(), &[10])?;
    let result = channel_of(owner, h).and_then(|ch| {
        // The client's table has its first page of blocks: the page below
        // is the pool's.
        let d = client.insert(Object::Channel(ch), Rights::NOTIFY | Rights::DUPLICATE)?;
        let used = |c: &Caller| process::quota(c.process).used();
        let before = (used(client), used(owner));
        let notify = u64::from(Rights::NOTIFY.0);
        let sessions = [1, 2].map(|label| client.created(n, &[d.0, notify, label, 10]));
        let after = (used(client), used(owner));
        let payer = sessions[0].and_then(|s| session_of(client, s)).map(session::payer);
        for s in sessions.into_iter().flatten() {
            client.close(s)?;
        }
        client.close(d)?;
        check(
            after == (before.0 + PAGE_SIZE, before.1),
            "the caller of handle_duplicate did not pay one page for its sessions, or the channel's owner paid",
        )?;
        check(
            payer == Ok(client.process),
            "the session does not name its caller as its payer",
        )
    });
    owner.close(h)?;
    cleanup::drain();
    result
}

/// Sessions of a closed channel go (spec 5.3, 6.8): the stage Close
/// empties the slot with CLIENT_GONE, and its session goes, queued at the
/// level of the portion that let it go (spec 7.7); a session whose slot
/// was queued with bits and whose copy is left stays, and so does one with
/// nothing queued, until their copies close. The channel goes after them,
/// and once the caller went the pages of its pools too.
pub fn sessions_of_a_closed_channel_go(_: &Boot) -> Result<(), &'static str> {
    // One round first: the pool of shells of the tests' processes keeps
    // the page it takes.
    Caller::new()?.release();
    let (sessions, channels, taken) = (session::in_use(), channel::in_use(), pages::taken());
    let c = Caller::new()?;
    let result = closed_sessions(&c, sessions);
    c.release();
    result?;
    check(
        session::in_use() == sessions && channel::in_use() == channels,
        "a session or the channel stayed after the channel closed",
    )?;
    check(
        pages::taken() == taken,
        "the pages of the pools did not go with the caller",
    )
}

fn closed_sessions(c: &Caller, sessions: usize) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let notify = u64::from(Rights::NOTIFY.0);
    let [idle, gone, posted] = [1, 2, 3].map(|label| c.created(n, &[h.0, notify, label, 10]));
    let (idle, gone, posted) = (idle?, gone?, posted?);
    c.succeeds(Call::Notify.number(), &[posted.0, 1], &[])?;
    c.close(gone)?;
    c.close(h)?;
    let queued = cleanup::len();
    cleanup::portion();
    let released = cleanup::top();
    cleanup::drain();
    let held = session::in_use() - sessions;
    c.close(idle)?;
    c.close(posted)?;
    cleanup::drain();
    check(
        queued == 1,
        "the closed channel did not go to its stage Close",
    )?;
    check(
        released == Some(CAUSE),
        "the stage Close did not let the session with CLIENT_GONE go at its level",
    )?;
    check(
        held == 2,
        "the stage Close did not let the session with CLIENT_GONE go, or let one with a copy go",
    )
}

/// Spec 15.2 (refusals): a process that holds the only handle with a label
/// dies (spec 5.3, 6.8). Its teardown runs at R, the level of its end, and
/// its stage Handles lets the last copy go, which posts CLIENT_GONE with
/// the label into the session's slot: nothing is there before, the
/// channel's owner takes the notice afterwards, and the session goes at
/// the priority of its slot, 20, which the receive runs at (spec 6.6,
/// 7.7).
pub fn client_gone_when_the_holder_dies(_: &Boot) -> Result<(), &'static str> {
    let (sessions, processes) = (session::in_use(), process::in_use());
    with_caller(|c| {
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let result = channel_of(c, h).and_then(|ch| holder_dies(c, h, ch));
        c.close(h)?;
        result
    })?;
    check(
        session::in_use() == sessions && process::in_use() == processes,
        "the session or the holder stayed",
    )
}

/// The level of the holder's end.
const HOLDER_END: u8 = 5;

fn holder_dies(c: &Caller, h: Handle, ch: NonNull<Channel>) -> Result<(), &'static str> {
    let holder = Caller::new()?;
    let result = (|| {
        let d = holder.insert(Object::Channel(ch), Rights::NOTIFY | Rights::DUPLICATE)?;
        let notify = u64::from(Rights::NOTIFY.0);
        holder.created(Call::HandleDuplicate.number(), &[d.0, notify, 0xD1E, 20])?;
        holder.close(d)?;
        // SAFETY: the holder's process is the test's.
        unsafe { process::end(holder.process, ProcessState::Killed, HOLDER_END) };
        let level = cleanup::top();
        c.fails(Call::Receive.number(), &[h.0, NO_WAIT], Error::WouldBlock)?;
        cleanup::drain();
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &labelled(0xD1E, CLIENT_GONE, 1),
        )?;
        let gone_at = cleanup::top();
        cleanup::drain();
        check(
            gone_at == Some(20),
            "the session did not go at the priority of its CLIENT_GONE",
        )?;
        check(
            level == Some(HOLDER_END) && label_of(c) == 0xD1E,
            "the holder's teardown did not run at the level of its end, or the label did not come",
        )
    })();
    holder.release();
    result
}

/// x1-x9 of a receive that took the exit notification of a child whose
/// exit channel carried `label`: bit 0, once (spec 7.9).
fn exit_notice(label: u64) -> [u64; 9] {
    let n = Notification {
        source: Source::Exit,
        label,
        bits: 1,
        count: 1,
    };
    n.to_words()[..9].try_into().expect("x1-x9")
}

/// The child behind the caller's handle `h`.
fn child_of(c: &Caller, h: Handle) -> Result<NonNull<Process>, &'static str> {
    // SAFETY: the caller's process is the test's.
    unsafe { c.process.as_ref() }
        .lookup(h, Rights::NONE, Object::process)
        .map_err(|_| "the handle does not name a process")
}

/// R, the level of a teardown, is at least the priority of the exit
/// notification, x4 (spec 7.7, 7.9): a child whose exit channel hears of
/// it at 20 ends at 5, and its teardown stands at 20 in the cleanup queue,
/// above a thread at 10 that is ready. The notification comes after it.
pub fn teardown_level_is_at_least_the_notice(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let result = c
            .created(
                Call::ProcessCreate.number(),
                &[CHILD_QUOTA, 16, 20, h.0, 20, 0],
            )
            .and_then(|child| {
                let level = child_of(c, child).map(|p| {
                    // SAFETY: the caller's handle holds the child.
                    unsafe { process::end(p, ProcessState::Killed, 5) };
                    cleanup::top()
                });
                cleanup::drain();
                c.close(child)?;
                c.succeeds(Call::Receive.number(), &[h.0, NO_WAIT], &exit_notice(0))?;
                check(
                    level == Ok(Some(20)),
                    "the teardown of a child that ended at 5 is not at its exit priority 20",
                )
            });
        c.close(h)?;
        result
    })
}

/// The slot of the exit notification lies in the child's shell and holds
/// it while it stands in the channel's queue (spec 6.5, 7.9): the parent
/// kills the child and closes its handle before it receives. The shell
/// stays, the notification comes, and after it the shell goes.
pub fn exit_notice_keeps_the_shell(_: &Boot) -> Result<(), &'static str> {
    let processes = process::in_use();
    with_caller(|c| {
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let result = c
            .created(
                Call::ProcessCreate.number(),
                &[CHILD_QUOTA, 16, 20, h.0, 10, 0],
            )
            .and_then(|child| {
                c.succeeds(Call::ProcessKill.number(), &[child.0], &[])?;
                c.close(child)?;
                cleanup::drain();
                let kept = process::in_use() == processes + 2;
                c.succeeds(Call::Receive.number(), &[h.0, NO_WAIT], &exit_notice(0))?;
                cleanup::drain();
                let gone = process::in_use() == processes + 1;
                check(
                    kept,
                    "the child's shell went while its exit notification stood in the channel",
                )?;
                check(gone, "the child's shell stayed after its exit notification")
            });
        c.close(h)?;
        result
    })?;
    check(
        process::in_use() == processes,
        "a process of the test stayed",
    )
}

/// A parent's end ends its child (spec 4), whose exit notification goes
/// into a channel of the parent: the parent's stage Handles closes the
/// channel, the stage Close takes the notification (spec 6.8, 7.9), and
/// the child's shell goes with it. Nothing of the tree stays.
pub fn notices_to_a_dying_parent_go_with_its_channel(_: &Boot) -> Result<(), &'static str> {
    let (processes, channels) = (process::in_use(), channel::in_use());
    let parent = Caller::new()?;
    let made = parent
        .created(Call::CreateChannel.number(), &[10])
        .and_then(|h| {
            parent.created(
                Call::ProcessCreate.number(),
                &[CHILD_QUOTA, 16, 20, h.0, 10, 0],
            )
        });
    // SAFETY: the parent's process is the test's.
    unsafe { process::end(parent.process, ProcessState::Killed, CAUSE) };
    cleanup::drain();
    parent.release();
    made?;
    check(
        process::in_use() == processes && channel::in_use() == channels,
        "the child, the parent or the channel stayed",
    )
}

/// x1-x9 of a receive that took `count` expiries of a timer made through
/// a handle with no label.
fn timer_notice(count: u32) -> [u64; 9] {
    let n = Notification {
        source: Source::Timer,
        label: 0,
        bits: 1,
        count,
    };
    n.to_words()[..9].try_into().expect("x1-x9")
}

/// The timer behind the caller's handle `h`.
fn timer_of(c: &Caller, h: Handle) -> Result<NonNull<Timer>, &'static str> {
    // SAFETY: the caller's process is the test's.
    unsafe { c.process.as_ref() }
        .lookup(h, Rights::NONE, Object::timer)
        .map_err(|_| "the handle does not name a timer")
}

/// A second from now in nanoseconds on the scale of clock_now.
fn a_second_away() -> u64 {
    timer::clock().ticks_to_ns(timer::now()) + 1_000_000_000
}

/// Runs `body` with a channel of the caller at 10, a timer on it at 10 and
/// the caller's handles to both; closes the handles afterwards.
fn with_timer(
    c: &Caller,
    body: impl FnOnce(Handle, Handle, NonNull<Timer>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let t = c.created(Call::TimerCreate.number(), &[h.0, 10]);
    let result = t.and_then(|t| {
        let result = timer_of(c, t).and_then(|tm| body(h, t, tm));
        // A test may have closed it already.
        let _ = process::close_handle(c.process, t, CAUSE);
        result
    });
    let _ = process::close_handle(c.process, h, CAUSE);
    result
}

/// timer_create stops at the caller's limits (spec 7.8, 10, 11): with the
/// caller's table full it fails with LIMIT_REACHED, and with its quota
/// spent with NO_MEMORY for a page of its pool of timers, with nothing
/// made; with every slot of the channel taken, LIMIT_REACHED comes before
/// the quota (spec 6.5). A good call returns a handle with
/// abi::OWNER_RIGHTS to a timer the caller pays for, not armed; timer_set
/// arms it at its deadline in ticks and timer_cancel takes it off the
/// heap, and timer_set on a closed channel fails with PEER_CLOSED and
/// leaves the timer armed as it was. The checks of the calls, the
/// caller's own ceiling among them, are the test init's.
pub fn timer_create_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let timers = timers::in_use();
    let c = Caller::new()?;
    let result = timer_create_cases(&c);
    c.release();
    result?;
    check(
        timers::in_use() == timers,
        "a timer of the test stayed in its pool",
    )
}

fn timer_create_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::TimerCreate.number();
    // First, while the caller's pool of timers has no page.
    let full = c.created(Call::CreateChannel.number(), &[10])?;
    let refused = fill_slots(c, full)
        .and_then(|()| with_used_quota(c, || c.fails(n, &[full.0, 30], Error::LimitReached)));
    c.close(full)?;
    cleanup::drain();
    refused?;
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let result = (|| {
        let timers = timers::in_use();
        with_used_quota(c, || {
            c.fails(n, &[h.0, 30], Error::NoMemory)?;
            with_full_table(c, n, &[h.0, 30])
        })?;
        cleanup::drain();
        check(
            timers::in_use() == timers,
            "a timer that did not fit stayed",
        )?;
        let t = c.created(n, &[h.0, 30])?;
        let result = timer_set_cases(c, [h, t]);
        c.close(t)?;
        result
    })();
    // The case of the closed channel closed it already.
    let _ = process::close_handle(c.process, h, CAUSE);
    result
}

/// Takes every slot of the caller's channel `h` but the slot of label 0
/// with sessions whose handles the caller closes: CLIENT_GONE keeps each
/// in the channel's queue (spec 5.3, 6.5).
fn fill_slots(c: &Caller, h: Handle) -> Result<(), &'static str> {
    for label in 1..u64::from(MAX_SLOTS) {
        let s = c.created(Call::HandleDuplicate.number(), &[h.0, 0, label, 10])?;
        c.close(s)?;
    }
    Ok(())
}

fn timer_set_cases(c: &Caller, handles: [Handle; 2]) -> Result<(), &'static str> {
    let [h, t] = handles;
    let (set, cancel) = (Call::TimerSet.number(), Call::TimerCancel.number());
    let tm = timer_of(c, t)?;
    // SAFETY: the caller's process is the test's.
    let rights = unsafe { c.process.as_ref() }.lookup(t, OWNER_RIGHTS, Object::timer);
    check(
        rights.is_ok() && timers::payer(tm) == c.process && timers::deadline(tm).is_none(),
        "the handle does not carry the owner's rights, the caller does not pay, or the timer is armed",
    )?;
    let far = a_second_away();
    let at = timer::clock().ns_to_ticks(far);
    c.succeeds(set, &[t.0, far], &[])?;
    check(
        timers::deadline(tm) == Some(at),
        "timer_set did not arm the timer",
    )?;
    c.succeeds(cancel, &[t.0], &[])?;
    c.succeeds(cancel, &[t.0], &[])?;
    check(
        timers::deadline(tm).is_none(),
        "timer_cancel left the timer armed",
    )?;
    c.succeeds(set, &[t.0, far], &[])?;
    // The last handle with RECEIVE goes: the channel closes (spec 6.8).
    c.close(h)?;
    c.fails(set, &[t.0, 0], Error::PeerClosed)?;
    check(
        timers::deadline(tm) == Some(at) && !timers::posted(tm),
        "timer_set on a closed channel changed the timer",
    )?;
    c.succeeds(cancel, &[t.0], &[])
}

/// timer_set rounds its deadline up to counter ticks (spec 10): for every
/// deadline of a stretch of 64 ns a second away, on the ticks and between
/// them, the timer stands in the heap at the first tick whose time, as
/// clock_now counts it, is not before the deadline; the tick before it is.
/// Only the heap shows a deadline a tick early: what a program sees is the
/// test init's timer_never_fires_early.
pub fn timer_set_rounds_the_deadline_up(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        with_timer(c, |_, t, tm| {
            let clock = timer::clock();
            let base = a_second_away();
            for deadline in base..base + 64 {
                c.succeeds(Call::TimerSet.number(), &[t.0, deadline], &[])?;
                let at = timers::deadline(tm).ok_or("the timer is not armed")?;
                check(
                    clock.ticks_to_ns(at) >= deadline && clock.ticks_to_ns(at - 1) < deadline,
                    "the timer's tick is not the first one at or after its deadline",
                )?;
            }
            Ok(())
        })
    })
}

/// A deadline the counter reached fires in timer_set itself (spec 10):
/// right after the call, with no interrupt in between, the timer's slot
/// stands in the channel's queue and the timer is in no heap. So it goes
/// for 0, for the time clock_now would give, and for an armed timer set
/// back into the past; each time receive takes one expiry, bit 0 once. Only
/// the kernel sees the post before an interrupt could make it: what a
/// program sees is the test init's timer_in_the_past_fires_at_once.
pub fn past_deadline_fires_within_timer_set(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        with_timer(c, |h, t, tm| {
            let (set, receive) = (Call::TimerSet.number(), Call::Receive.number());
            let now = timer::clock().ticks_to_ns(timer::now());
            for (armed, past) in [(false, 0), (false, now), (true, 1)] {
                if armed {
                    c.succeeds(set, &[t.0, a_second_away()], &[])?;
                }
                c.succeeds(set, &[t.0, past], &[])?;
                check(
                    timers::posted(tm) && timers::deadline(tm).is_none(),
                    "a deadline in the past did not fire in timer_set",
                )?;
                c.succeeds(receive, &[h.0, NO_WAIT], &timer_notice(1))?;
            }
            Ok(())
        })
    })
}

/// A timer whose last handle went is dying (spec 7.7): the cleanup queue
/// holds it at CAUSE, and the heap of its level still does until its
/// portion. The firing of its level, 10, at its deadline, a second away,
/// takes it off the heap and posts nothing; its own portion then lets it
/// go.
pub fn dying_timer_does_not_fire(_: &Boot) -> Result<(), &'static str> {
    let timers = timers::in_use();
    with_caller(|c| {
        with_timer(c, |h, t, tm| {
            c.succeeds(Call::TimerSet.number(), &[t.0, a_second_away()], &[])?;
            let at = timers::deadline(tm).ok_or("the timer is not armed")?;
            c.close(t)?;
            let queued = cleanup::len();
            timers::fire_at(10, at);
            let (posted, armed) = (timers::posted(tm), timers::deadline(tm).is_some());
            c.fails(Call::Receive.number(), &[h.0, NO_WAIT], Error::WouldBlock)?;
            cleanup::drain();
            check(queued == 1, "the timer's last handle did not queue it")?;
            check(
                !posted && !armed,
                "a dying timer fired, or stayed in the heap",
            )
        })
    })?;
    check(timers::in_use() == timers, "the dying timer stayed")
}

/// Timers the test of the firing of a level arms: more than two portions.
const FIRST_FIRINGS: usize = 40;

/// A level ends its firing before what came to it later (spec 7.7, 10):
/// with FIRST_FIRINGS timers of level 10 expired at their deadline, a
/// second away, and a channel whose last reference went at 10 queued
/// behind, the first portion of the firing, which the test runs at that
/// deadline, posts FIRE_PORTION of them and puts the level's item back at
/// the head of level 10. The next portion is the firing's again, and the
/// channel is still there after it.
pub fn a_level_finishes_its_firing_first(_: &Boot) -> Result<(), &'static str> {
    let counts = (timers::in_use(), channel::in_use());
    with_caller(|c| {
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let mut made = [None; FIRST_FIRINGS];
        let result = channel_of(c, h).and_then(|ch| {
            let at = timer::now() + timer::clock().ns_to_ticks(1_000_000_000);
            for (n, t) in made.iter_mut().enumerate() {
                let tm = timers::create(c.process, ch, 0, 10).map_err(|_| "no timer")?;
                *t = Some(tm);
                timers::set(tm, at + n as u64, CAUSE).map_err(|_| "a timer was not armed")?;
            }
            let later = channel::create(c.process, 10).map_err(|_| "no channel")?;
            // SAFETY: the reference `create` handed out goes, the last one:
            // the channel is queued at 10.
            unsafe { channel::release(later, Rights::NONE, 10) };
            let alive = channel::in_use();
            let last = at + FIRST_FIRINGS as u64;
            timers::fire_at(10, last);
            let first = posted_of(&made);
            cleanup::portion();
            let (second, kept) = (posted_of(&made), channel::in_use() == alive);
            cleanup::drain();
            check(
                first == kcore::timer::FIRE_PORTION && second == first,
                "the first portion of the firing did not post its portion",
            )?;
            check(kept, "a channel queued later came before the firing")
        });
        for t in made.into_iter().flatten() {
            // SAFETY: the test's reference goes.
            unsafe { timers::release(t, CAUSE) };
        }
        let _ = process::close_handle(c.process, h, CAUSE);
        cleanup::drain();
        result
    })?;
    check(
        (timers::in_use(), channel::in_use()) == counts,
        "a timer or a channel of the test stayed",
    )
}

/// How many of `made` posted.
fn posted_of(made: &[Option<NonNull<Timer>>]) -> usize {
    made.iter()
        .flatten()
        .filter(|&&t| timers::posted(t))
        .count()
}

/// A thread whose count of requests reached its end gets BAD_STATE from
/// send (spec 6.1, 11): after the checks of the description and of the
/// handle, before the state of the channel, a closed one too; x0 alone
/// changes, and nothing waits.
pub fn call_counter_runs_out_as_bad_state(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let copies = channel_of(c, h).and_then(|ch| {
            Ok([
                c.insert(Object::Channel(ch), Rights::SEND)?,
                c.insert(Object::Channel(ch), Rights::NOTIFY)?,
            ])
        });
        let index = thread::index(c.thread);
        sched::locked(|k| k.tokens.skip_to(index, MAX_COUNT));
        let result = copies.and_then(|[send, notify]| {
            let n = Call::Send.number();
            c.fails(n, &[send.0, 1 << 15], Error::InvalidArgs)?;
            c.fails(n, &[notify.0, 0], Error::AccessDenied)?;
            c.fails(n, &[send.0, 8, 1, 2], Error::BadState)?;
            c.fails(n, &[send.0, NO_WAIT], Error::BadState)?;
            // The last handle with RECEIVE goes, and the channel closes.
            c.close(h)?;
            c.fails(n, &[send.0, 0], Error::BadState)?;
            c.close(send)?;
            c.close(notify)
        });
        cleanup::drain();
        result
    })
}

/// The system has thread::THREADS numbers (spec 8, 11): with all but one
/// taken, thread_create makes a thread and fails the next with
/// LIMIT_REACHED, x0 alone changing; with no quota left too, the limit
/// comes first. The numbers come back.
pub fn thread_limit_of_the_system(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), OWNER_RIGHTS)?;
        let mut taken = [0u16; THREADS];
        let n = sched::locked(|k| {
            let mut n = 0;
            while k.tokens.available() > 1 {
                taken[n] = k.tokens.alloc(NonNull::dangling()).expect("a free number");
                n += 1;
            }
            n
        });
        let create = Call::ThreadCreate.number();
        let args = |buffer| thread_args(own.0, USER_VA as u64, 0x80_1000, 10, FIFO, buffer);
        let result = c.created(create, &args(BUFFER)).and_then(|t| {
            let past = c
                .fails(create, &args(BUFFER + PAGE_SIZE), Error::LimitReached)
                .and_then(|()| {
                    with_used_quota(c, || {
                        c.fails(create, &args(BUFFER + PAGE_SIZE), Error::LimitReached)
                    })
                });
            c.close(t)?;
            past
        });
        sched::locked(|k| taken[..n].iter().for_each(|&i| k.tokens.free(i)));
        c.close(own)?;
        result
    })
}

/// Numbers go back to the table as their threads end, and with the
/// portion of a thread that never started (spec 6.1, 7.7): a thread that
/// cannot be made for want of quota takes none, and 1000 threads made,
/// started and ended one after another, then 1000 made and let go without
/// a start, leave as many numbers free as there were.
pub fn thread_numbers_come_back(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let before = sched::locked(|k| k.tokens.available());
        no_quota_takes_no_number(c)?;
        for _ in 0..1000 {
            let t = thread::create(c.process, USER_VA, USER_VA, 0, 10, Policy::Fifo)
                .map_err(|_| "no thread")?;
            let started = thread::start(t);
            // SAFETY: the test's reference goes after the thread left the
            // scheduler, as a kill leaves it.
            unsafe {
                sched::exit(t, CAUSE);
                thread::release(t, CAUSE);
            }
            started.map_err(|_| "a thread did not start")?;
            cleanup::drain();
        }
        for _ in 0..1000 {
            let t = thread::create(c.process, USER_VA, USER_VA, 0, 10, Policy::Fifo)
                .map_err(|_| "no thread")?;
            // SAFETY: the test's reference, the only one, goes; the thread
            // never started.
            unsafe { thread::release(t, CAUSE) };
            cleanup::drain();
        }
        check(
            sched::locked(|k| k.tokens.available()) == before,
            "thread numbers did not come back",
        )
    })
}

/// With the caller's quota used up, threads go into the free places of its
/// pool of threads until the pool needs a page: then `thread::create`
/// fails with NO_MEMORY and takes no number (spec 7.8). The threads made
/// go again.
fn no_quota_takes_no_number(c: &Caller) -> Result<(), &'static str> {
    let before = sched::locked(|k| k.tokens.available());
    let mut made = [None; 8];
    let result = with_used_quota(c, || {
        for (n, m) in made.iter_mut().enumerate() {
            match thread::create(c.process, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
                Ok(t) => *m = Some(t),
                Err(e) => {
                    return check(
                        e == Error::NoMemory
                            && sched::locked(|k| k.tokens.available()) == before - n,
                        "a thread_create out of quota took a number",
                    );
                }
            }
        }
        Err("threads did not run out of quota")
    });
    for t in made.into_iter().flatten() {
        // SAFETY: the test's reference, the only one, goes; the thread
        // never started.
        unsafe { thread::release(t, CAUSE) };
    }
    cleanup::drain();
    result
}

/// A memory object of `pages` pages that `c` makes with mem_create, entry
/// after entry until the call ends (`Caller::again`), and its handle: x0
/// is 0, x1 the handle, with abi::MEMORY_RIGHTS, and nothing else changes.
fn make_memory(c: &Caller, pages: u64) -> Result<(Handle, NonNull<Memory>), &'static str> {
    let n = Call::MemCreate.number();
    let args = [pages * PAGE_SIZE, 0];
    let mut got = c.call(n, &args);
    while thread::long(c.thread).is_some() {
        got = c.again(n);
    }
    let mut want = with_marks(&args);
    want[0] = 0;
    want[1] = got[1];
    if got != want || got[1] == 0 {
        kprintln!("mem_create with {args:x?}: x0-x9 are {got:x?}");
        return Err("mem_create failed");
    }
    let h = Handle(got[1]);
    // SAFETY: the caller's process is the test's.
    let m = unsafe { c.process.as_ref() }.lookup(h, MEMORY_RIGHTS, Object::memory);
    Ok((
        h,
        m.map_err(|_| "the handle of mem_create lacks MEMORY_RIGHTS")?,
    ))
}

/// The kernel's timer fires at once, and its interrupt stays pending while
/// `body` runs; then it is taken and the timer is off.
fn with_interrupt_pending(
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    nothing_pending("an interrupt was pending before the test")?;
    timer::arm(timer::now());
    while !arch::irq_pending() {}
    let result = body();
    let ack = wait_for_timer();
    timer::disarm();
    gic::end(ack?);
    result
}

/// mem_create stops at the caller's resources (spec 7.3, 11): with its
/// quota spent it fails with NO_MEMORY for a page of its pool of memory
/// objects, and with LIMIT_REACHED first when its table is full; with a
/// free place in the pool, one page short of the object's budget, 16 pages
/// and the node of their list, it fails with NO_MEMORY, and with the whole
/// budget left it makes the object. A call that fails makes nothing,
/// changes x0 alone and keeps no charge. The rest of the checks are the
/// test init's (mem_create_checks_its_arguments).
pub fn mem_create_over_the_quota_is_no_memory(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    with_caller(|c| {
        let n = Call::MemCreate.number();
        let args = [16 * PAGE_SIZE, 0];
        // The table's first chunk, so that no call below takes one.
        let resource = c.insert(Object::Resource, Rights::NONE)?;
        let used = process::quota(c.process).used();
        with_used_quota(c, || {
            c.fails(n, &args, Error::NoMemory)?;
            with_full_table(c, n, &args)
        })?;
        check(
            process::quota(c.process).used() == used && memory::in_use() == objects,
            "a mem_create that failed kept an object or a charge",
        )?;
        // A free place in the pool.
        let (h, _) = make_memory(c, 1)?;
        c.close(h)?;
        cleanup::drain();
        with_quota_left(c, 16 * PAGE_SIZE, || c.fails(n, &args, Error::NoMemory))?;
        with_quota_left(c, 17 * PAGE_SIZE, || {
            let (h, _) = make_memory(c, 16)?;
            c.close(h)
        })?;
        cleanup::drain();
        c.close(resource)
    })?;
    check(
        memory::in_use() == objects,
        "an object of the test stayed in its pool",
    )
}

/// A memory object pays for itself from its payer's quota at once and
/// gives it all back with its place (spec 7.3, 7.5): an object of 600
/// pages, whose list takes a node of two nodes, charges the caller, its
/// payer, 603 pages and takes as many frames, and its object_info counts
/// every page; once its handle closes and its portions ran, the caller's
/// used quota and the free frames are what they were. An object made and
/// closed first leaves a free place in the caller's pool.
pub fn object_pays_its_budget_back_to_the_payer(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let (h, _) = make_memory(c, 1)?;
        c.close(h)?;
        cleanup::drain();
        let (used, free) = (process::quota(c.process).used(), phys::free_frames());
        let (h, m) = make_memory(c, 600)?;
        let charged = process::quota(c.process).used() - used;
        let taken = free - phys::free_frames();
        let (info, payer) = (memory::info(m), memory::payer(m));
        c.close(h)?;
        cleanup::drain();
        check(
            charged == 603 * PAGE_SIZE && taken == 603,
            "the object did not charge its pages and nodes to its payer at once",
        )?;
        check(
            payer == c.process
                && info
                    == MemoryInfo {
                        size: 600 * PAGE_SIZE,
                        pages: 600,
                        mappings: 0,
                    },
            "the caller does not pay for the object, or it is not whole",
        )?;
        check(
            process::quota(c.process).used() == used && phys::free_frames() == free,
            "the object did not give its budget back to its payer",
        )
    })
}

/// The frames of a new object read as zero, though the object before it
/// left a pattern in them (spec 7.6): an object of 64 pages gets the
/// pattern in every word of its frames through the linear map and goes;
/// the next object of 64 pages takes some of those frames again, and every
/// word of each of its frames reads 0.
pub fn new_object_is_zeroed(_: &Boot) -> Result<(), &'static str> {
    const PAGES: usize = 64;
    let word = |pa: u64, i: usize| (LINEAR_BASE + pa as usize + 8 * i) as *mut u64;
    with_caller(|c| {
        let (h, m) = make_memory(c, PAGES as u64)?;
        let used: [u64; PAGES] = core::array::from_fn(|i| memory::frame(m, i));
        for pa in used {
            for i in 0..512 {
                // SAFETY: the frame is the object's, which the test holds,
                // and the linear map reaches it.
                unsafe { word(pa, i).write_volatile(0x5A5A_5A5A_5A5A_5A5A) };
            }
        }
        c.close(h)?;
        cleanup::drain();
        let (h, m) = make_memory(c, PAGES as u64)?;
        let again: [u64; PAGES] = core::array::from_fn(|i| memory::frame(m, i));
        let reused = again.iter().filter(|pa| used.contains(pa)).count();
        // SAFETY: as above, for the new object.
        let zero = again
            .iter()
            .all(|&pa| (0..512).all(|i| unsafe { word(pa, i).read_volatile() } == 0));
        c.close(h)?;
        check(
            reused > 0,
            "the new object took none of the frames of the one before",
        )?;
        check(zero, "a frame of a new object holds what was there before")
    })
}

/// mem_create goes in portions of memory::CREATE_PORTION pages and starts
/// over at its `svc` when an interrupt is pending after a portion (spec
/// 7.7): with the kernel's timer pending all along, each entry of a call
/// for 20 pages takes one portion, leaves x0-x9 as they were and ELR on
/// the `svc`, and the object the thread's long call holds has 8 and then
/// 16 pages; the third entry takes the rest, ends the call and returns the
/// handle of a whole object. The portions count toward the longest portion
/// (KERNEL_STATS x5).
pub fn create_resumes_where_it_stopped(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| with_interrupt_pending(|| resumed_cases(c)))
}

fn resumed_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::MemCreate.number();
    let args = [20 * PAGE_SIZE, 0];
    // SAFETY: the thread is the test's and never runs.
    let elr = || unsafe { c.thread.as_ref() }.regs.elr;
    let at_svc = elr() - 4;
    cleanup::take_longest();
    let mut got = c.call(n, &args);
    let mut filled = [0; 2];
    for f in &mut filled {
        let Some(Long::Create(m)) = thread::long(c.thread) else {
            return Err("mem_create did not stop after a portion");
        };
        check(
            got == with_marks(&args) && elr() == at_svc,
            "a call that starts over changed its registers or left its svc",
        )?;
        *f = memory::filled(m);
        got = c.again(n);
    }
    check(
        filled == [8, 16],
        "the object did not grow a portion an entry",
    )?;
    let mut want = with_marks(&args);
    want[0] = 0;
    want[1] = got[1];
    check(
        thread::long(c.thread).is_none() && got == want,
        "the third entry did not end the call with the handle",
    )?;
    check(
        cleanup::longest() > 0,
        "the portions of mem_create did not count toward the longest portion",
    )?;
    let h = Handle(got[1]);
    // SAFETY: the caller's process is the test's.
    let m = unsafe { c.process.as_ref() }.lookup(h, MEMORY_RIGHTS, Object::memory);
    let whole = m.is_ok_and(|m| memory::info(m).pages == 20);
    c.close(h)?;
    check(whole, "the handle does not name a whole object of 20 pages")
}

/// A mem_create whose caller's process ends between two portions (spec
/// 7.7): the object, which only the thread's long call holds, goes with
/// the thread's buffer at the stage Buffers, and its frames and its place
/// come back.
pub fn killed_creator_lets_the_object_go(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    let memory = phys::free_frames() + pages::taken() as u64;
    let c = Caller::new()?;
    let mut stopped = false;
    let pending = with_interrupt_pending(|| {
        c.call(Call::MemCreate.number(), &[64 * PAGE_SIZE, 0]);
        stopped = matches!(thread::long(c.thread), Some(Long::Create(m)) if memory::filled(m) == 8);
        Ok(())
    });
    // SAFETY: the test holds a reference to the process.
    let ended = unsafe { process::end(c.process, ProcessState::Killed, CAUSE) };
    cleanup::drain();
    let went = memory::in_use() == objects;
    c.release();
    pending?;
    check(stopped && ended, "mem_create did not stop after a portion")?;
    check(went, "the object did not go with the teardown of its maker")?;
    check(
        phys::free_frames() + pages::taken() as u64 == memory,
        "the object's frames or its place did not come back",
    )
}

/// The room for the handle of mem_create is made on its first entry, and
/// other threads of the caller's process may take it between two portions
/// (spec 7.3): the call then fails with LIMIT_REACHED at its end, x0
/// alone, and the object, whole by then, is queued at the caller's level
/// and goes with its frames and its place.
pub fn full_table_at_the_end_lets_the_object_go(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    let memory = phys::free_frames() + pages::taken() as u64;
    with_caller(|c| {
        let n = Call::MemCreate.number();
        let args = [64 * PAGE_SIZE, 0];
        let mut first = [0; 10];
        with_interrupt_pending(|| {
            first = c.call(n, &args);
            Ok(())
        })?;
        let mut filler = [None; LIMIT as usize];
        for slot in &mut filler {
            match process::insert_handle(c.process, Object::Resource, Rights::NONE) {
                Ok(h) => *slot = Some(h),
                Err(_) => break,
            }
        }
        let last = c.again(n);
        let queued = cleanup::top();
        cleanup::drain();
        for h in filler.into_iter().flatten() {
            c.close(h)?;
        }
        let mut want = with_marks(&args);
        check(first == want, "mem_create did not stop after a portion")?;
        want[0] = Error::LimitReached.code();
        check(
            last == want && thread::long(c.thread).is_none(),
            "a full table at the end did not fail mem_create with LIMIT_REACHED alone",
        )?;
        check(
            queued == Some(10),
            "the object was not queued at the caller's level",
        )
    })?;
    check(
        memory::in_use() == objects && phys::free_frames() + pages::taken() as u64 == memory,
        "the object that found no room stayed",
    )
}

/// A thread whose next entry makes another call than its long call gives
/// the long call up (spec 7.7): mem_create stops after a portion, and the
/// next entry, handle_close on the registers mem_create left, gives the
/// call up in a stretch of its own, which counts toward the longest
/// portion (KERNEL_STATS x5); with the kernel's timer pending that entry
/// starts over at its `svc`, x0-x9 as they were, and the entry after it
/// runs handle_close, which fails with BAD_HANDLE in x0 alone. The object,
/// which only the long call held, is queued at the thread's level and
/// goes with its frames and its budget.
pub fn another_call_gives_the_long_call_up(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    with_caller(|c| {
        let (h, _) = make_memory(c, 1)?;
        c.close(h)?;
        cleanup::drain();
        let (used, free) = (process::quota(c.process).used(), phys::free_frames());
        let args = [64 * PAGE_SIZE, 0];
        // SAFETY: the thread is the test's and never runs.
        let elr = || unsafe { c.thread.as_ref() }.regs.elr;
        let at_svc = elr() - 4;
        let (mut stopped, mut given_up, mut counted) = (false, false, false);
        with_interrupt_pending(|| {
            c.call(Call::MemCreate.number(), &args);
            stopped = thread::long(c.thread).is_some();
            cleanup::take_longest();
            let got = c.again(Call::HandleClose.number());
            counted = cleanup::longest() > 0;
            given_up =
                got == with_marks(&args) && elr() == at_svc && thread::long(c.thread).is_none();
            Ok(())
        })?;
        let got = c.again(Call::HandleClose.number());
        let queued = cleanup::top();
        cleanup::drain();
        let mut want = with_marks(&args);
        want[0] = Error::BadHandle.code();
        check(stopped, "mem_create did not stop after a portion")?;
        check(
            given_up,
            "the entry that gave the call up did not start over at its svc as it was",
        )?;
        check(
            counted,
            "giving the call up did not count toward the longest portion",
        )?;
        check(
            got == want && thread::long(c.thread).is_none(),
            "another call did not run as itself or kept the long call",
        )?;
        check(
            queued == Some(10),
            "the object did not go at the thread's level",
        )?;
        check(
            process::quota(c.process).used() == used && phys::free_frames() == free,
            "the object of the call given up kept its frames or its budget",
        )
    })?;
    check(
        memory::in_use() == objects,
        "the object of the call given up stayed",
    )
}

/// Pages of the objects of the tests of long changes of a mapping: four
/// portions of process::PORTION.
const LONG_PAGES: u64 = 128;

/// A process with no thread for `c` to map into, the target of a change,
/// and `c`'s handle to it with abi::OWNER_RIGHTS; the test keeps its own
/// reference.
fn target_of(c: &Caller) -> Result<(NonNull<Process>, Handle), &'static str> {
    let t = process::create_root(QUOTA, LIMIT, CEILING).map_err(|_| "no process")?;
    match c.insert(Object::Process(t), OWNER_RIGHTS) {
        Ok(h) => Ok((t, h)),
        Err(e) => {
            // SAFETY: the process is the test's, and nothing uses it afterwards.
            unsafe { process::release(t, CAUSE) };
            Err(e)
        }
    }
}

/// Lets the test's reference to a target go; its teardown runs.
fn release_target(t: NonNull<Process>) {
    // SAFETY: the reference is the test's, and nothing uses it afterwards.
    unsafe { process::release(t, CAUSE) };
    cleanup::drain();
}

/// mem_map by `c` of `pages` pages of object `m` from page 0 at `va` of
/// the process behind `target`, with `access`: 0 in x0 alone, however
/// many entries it takes.
fn map_whole(
    c: &Caller,
    target: Handle,
    m: Handle,
    pages: u64,
    va: usize,
    access: Access,
) -> Result<(), &'static str> {
    let n = Call::MemMap.number();
    let args = [target.0, m.0, 0, pages * PAGE_SIZE, va as u64, access.raw()];
    let mut got = c.call(n, &args);
    while thread::long(c.thread).is_some() {
        got = c.again(n);
    }
    let mut want = with_marks(&args);
    want[0] = 0;
    if got == want {
        return Ok(());
    }
    kprintln!("mem_map with {args:x?}: x0-x9 are {got:x?}");
    Err("mem_map failed")
}

/// mem_unmap by `c` of the mapping of `pages` pages at `va` of the process
/// behind `target`: 0 in x0 alone, however many entries it takes.
fn unmap_whole(c: &Caller, target: Handle, pages: u64, va: usize) -> Result<(), &'static str> {
    let n = Call::MemUnmap.number();
    let args = [target.0, va as u64, pages * PAGE_SIZE];
    let mut got = c.call(n, &args);
    while thread::long(c.thread).is_some() {
        got = c.again(n);
    }
    let mut want = with_marks(&args);
    want[0] = 0;
    check(got == want, "mem_unmap failed")
}

/// Whether page `va` of `p` translates.
fn mapped(p: NonNull<Process>, va: usize) -> bool {
    process::translate(p, va).is_some()
}

/// A mapping's tables are the target's to pay for, whoever maps (spec
/// 7.5): a caller maps 4 pages of its object into a new process, and every
/// frame the call took, the tables and the page of the pool that holds the
/// table of mappings, is charged to that process; the caller's quota does
/// not move.
pub fn mapping_tables_are_paid_by_the_target(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let (h, _) = make_memory(c, 4)?;
        let (t, th) = target_of(c)?;
        let (own, used, free) = (
            process::quota(c.process).used(),
            process::quota(t).used(),
            phys::free_frames(),
        );
        let result = map_whole(c, th, h, 4, USER_VA, Access::ReadWrite);
        let taken = free - phys::free_frames();
        let charged = process::quota(t).used() - used;
        let paid = process::quota(c.process).used() - own;
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        result?;
        check(
            taken >= 4 && charged == taken * PAGE_SIZE,
            "the tables and the table of mappings were not charged to the target",
        )?;
        check(paid == 0, "the caller paid for the target's mapping")
    })
}

/// A mapping whose tables do not fit in the target's quota maps nothing
/// (spec 7.5, 11): with a page less than the most tables a page may take,
/// 3, left in the quota of the target, mem_map of a page in a region of
/// 512 GiB with no table yet fails with NO_MEMORY in x0 alone, the page
/// does not translate, the quota is what it was, and no entry stays; with
/// the three pages left it maps and takes all three. Then 63 more
/// mappings of the page in that region, whose tables are there, fill the
/// table of mappings, and with two pages left a 65th fails with
/// LIMIT_REACHED in x0 alone: the place in the table comes before the
/// charge for tables (spec 11). A mapping made and unmapped first leaves
/// the table of mappings.
pub fn map_that_does_not_fit_maps_nothing(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let (h, m) = make_memory(c, 1)?;
        let (t, th) = target_of(c)?;
        let far = USER_VA + 512 * GIB as usize;
        let result = map_whole(c, th, h, 1, USER_VA, Access::Read)
            .and_then(|()| unmap_whole(c, th, 1, USER_VA))
            .and_then(|()| no_room_cases(c, t, th, h, m, far));
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        result
    })
}

fn no_room_cases(
    c: &Caller,
    t: NonNull<Process>,
    th: Handle,
    h: Handle,
    m: NonNull<Memory>,
    far: usize,
) -> Result<(), &'static str> {
    let n = Call::MemMap.number();
    let args = [th.0, h.0, 0, PAGE_SIZE, far as u64, Access::Read.raw()];
    let used = process::quota(t).used();
    with_left(t, 2 * PAGE_SIZE, || c.fails(n, &args, Error::NoMemory))?;
    check(
        !mapped(t, far)
            && process::quota(t).used() == used
            && process::mappings(t) == 0
            && memory::info(m).mappings == 0,
        "a mapping that did not fit left a page, a charge or an entry",
    )?;
    with_left(t, 3 * PAGE_SIZE, || c.succeeds(n, &args, &[]))?;
    check(mapped(t, far), "a mapping whose tables fit did not map")?;
    let at = |i: usize| far + i * PAGE;
    let full = (1..abi::MAX_MAPPINGS as usize)
        .try_for_each(|i| map_whole(c, th, h, 1, at(i), Access::Read));
    let beyond = [
        th.0,
        h.0,
        0,
        PAGE_SIZE,
        at(abi::MAX_MAPPINGS as usize) as u64,
        Access::Read.raw(),
    ];
    let limit = full.and_then(|()| {
        with_left(t, 2 * PAGE_SIZE, || {
            c.fails(n, &beyond, Error::LimitReached)
        })
    });
    for i in 0..abi::MAX_MAPPINGS as usize {
        if process::mapping(t, at(i), 1).is_some() {
            unmap_whole(c, th, 1, at(i))?;
        }
    }
    limit
}

/// A mapping gives back what it paid for tables and did not take (spec
/// 7.5): the first page in a new region takes three tables and the table
/// of mappings, and the target is charged for exactly what the call took;
/// the next page of the region, whose bound is three tables too, takes
/// none and leaves the quota of the target as it was.
pub fn prepaid_tables_come_back(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let (h, _) = make_memory(c, 2)?;
        let (t, th) = target_of(c)?;
        let (used, free) = (process::quota(t).used(), phys::free_frames());
        let first = map_whole(c, th, h, 1, USER_VA, Access::Read);
        let (taken, charged) = (free - phys::free_frames(), process::quota(t).used() - used);
        let (used, free) = (process::quota(t).used(), phys::free_frames());
        let second = first.and_then(|()| map_whole(c, th, h, 1, USER_VA + PAGE, Access::Read));
        let again = (free - phys::free_frames(), process::quota(t).used() - used);
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        second?;
        check(
            taken >= 4 && charged == taken * PAGE_SIZE,
            "the target was not charged for exactly what its first mapping took",
        )?;
        check(
            again == (0, 0),
            "a mapping that took no table kept a charge for tables",
        )
    })
}

/// A mem_map whose caller's process ends between two portions keeps the
/// pages it mapped (spec 7.7): with an interrupt pending all along, two
/// entries map two portions of an object of LONG_PAGES pages into a
/// target whose tables exist, each counting toward the longest portion
/// (KERNEL_STATS x5); once the caller's process went, the target has a
/// mapping of those pages alone, idle, which holds the object, the rest
/// does not translate, and what the call paid for tables came back.
pub fn abandoned_map_keeps_its_prefix(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    let c = Caller::new()?;
    let result = abandoned_map(&c);
    c.release();
    result?;
    check(
        memory::in_use() == objects,
        "the object stayed after its mapping went",
    )
}

fn abandoned_map(c: &Caller) -> Result<(), &'static str> {
    let (h, m) = make_memory(c, LONG_PAGES)?;
    let (t, th) = target_of(c)?;
    let done = 2 * u64::from(process::PORTION);
    let n = Call::MemMap.number();
    let args = [
        th.0,
        h.0,
        0,
        LONG_PAGES * PAGE_SIZE,
        USER_VA as u64,
        Access::ReadWrite.raw(),
    ];
    let result = map_whole(c, th, h, 1, USER_VA, Access::Read)
        .and_then(|()| unmap_whole(c, th, 1, USER_VA))
        .and_then(|()| {
            let used = process::quota(t).used();
            let mut counted = 0;
            with_interrupt_pending(|| {
                cleanup::take_longest();
                c.call(n, &args);
                c.again(n);
                counted = cleanup::longest();
                Ok(())
            })?;
            // SAFETY: the test holds a reference to the process.
            unsafe { process::end(c.process, ProcessState::Killed, CAUSE) };
            cleanup::drain();
            check(
                counted > 0,
                "the portions of mem_map did not count toward the longest portion",
            )?;
            let kept = process::mapping(t, USER_VA, done);
            check(
                kept.is_some_and(|k| !k.is_busy() && k.object == m && k.offset == 0),
                "the mapping did not keep its mapped pages alone, idle",
            )?;
            check(
                mapped(t, USER_VA + (done as usize - 1) * PAGE)
                    && !mapped(t, USER_VA + done as usize * PAGE)
                    && memory::info(m).mappings == 1,
                "the pages of the mapping do not translate as it says",
            )?;
            check(
                process::quota(t).used() == used,
                "what the call paid for tables did not come back",
            )
        });
    release_target(t);
    result
}

/// A mem_unmap whose caller's process ends between two portions keeps the
/// pages it did not unmap (spec 7.7): with an interrupt pending all along,
/// two entries unmap two portions of a mapping of LONG_PAGES pages; once
/// the caller's process went, the mapping starts past them with the rest
/// of the pages and their offset in the object, idle, and only those
/// translate.
pub fn abandoned_unmap_keeps_the_rest(_: &Boot) -> Result<(), &'static str> {
    let c = Caller::new()?;
    let result = abandoned_unmap(&c);
    c.release();
    result
}

fn abandoned_unmap(c: &Caller) -> Result<(), &'static str> {
    let (h, m) = make_memory(c, LONG_PAGES)?;
    let (t, th) = target_of(c)?;
    let done = 2 * u64::from(process::PORTION);
    let rest = USER_VA + done as usize * PAGE;
    let n = Call::MemUnmap.number();
    let args = [th.0, USER_VA as u64, LONG_PAGES * PAGE_SIZE];
    let result = map_whole(c, th, h, LONG_PAGES, USER_VA, Access::ReadWrite).and_then(|()| {
        with_interrupt_pending(|| {
            c.call(n, &args);
            c.again(n);
            Ok(())
        })?;
        // SAFETY: the test holds a reference to the process.
        unsafe { process::end(c.process, ProcessState::Killed, CAUSE) };
        cleanup::drain();
        let kept = process::mapping(t, rest, LONG_PAGES - done);
        check(
            kept.is_some_and(|k| !k.is_busy() && k.object == m && u64::from(k.offset) == done),
            "the mapping did not keep the pages the call did not unmap, idle",
        )?;
        check(
            !mapped(t, USER_VA) && !mapped(t, rest - PAGE) && mapped(t, rest),
            "the pages of the mapping do not translate as it says",
        )
    });
    release_target(t);
    result
}

/// A mem_protect whose caller's process ends between two portions leaves
/// its mapping idle (spec 7.7): with an interrupt pending all along, two
/// entries give two portions of a mapping of LONG_PAGES pages, RW, access
/// R; once the caller's process went, the mapping is whole and idle, and
/// the pages of those portions show R and the rest RW.
pub fn abandoned_protect_goes_idle(_: &Boot) -> Result<(), &'static str> {
    let c = Caller::new()?;
    let result = abandoned_protect(&c);
    c.release();
    result
}

fn abandoned_protect(c: &Caller) -> Result<(), &'static str> {
    let (h, m) = make_memory(c, LONG_PAGES)?;
    let (t, th) = target_of(c)?;
    let done = 2 * u64::from(process::PORTION);
    let n = Call::MemProtect.number();
    let args = [
        th.0,
        USER_VA as u64,
        LONG_PAGES * PAGE_SIZE,
        Access::Read.raw(),
    ];
    let result = map_whole(c, th, h, LONG_PAGES, USER_VA, Access::ReadWrite).and_then(|()| {
        with_interrupt_pending(|| {
            c.call(n, &args);
            c.again(n);
            Ok(())
        })?;
        // SAFETY: the test holds a reference to the process.
        unsafe { process::end(c.process, ProcessState::Killed, CAUSE) };
        cleanup::drain();
        let kept = process::mapping(t, USER_VA, LONG_PAGES);
        check(
            kept.is_some_and(|k| !k.is_busy() && k.object == m),
            "the mapping of an abandoned mem_protect did not go idle",
        )?;
        let shows = |page: u64, attrs: Attrs| {
            process::translate(t, USER_VA + page as usize * PAGE)
                .is_some_and(|(pa, d)| d == page_descriptor(pa, attrs))
        };
        check(
            shows(0, Attrs::USER_RODATA)
                && shows(done - 1, Attrs::USER_RODATA)
                && shows(done, Attrs::USER_DATA)
                && shows(LONG_PAGES - 1, Attrs::USER_DATA),
            "the pages of an abandoned mem_protect do not show the access its portions gave",
        )
    });
    release_target(t);
    result
}

/// A target that ends between two portions of a mem_map ends the call
/// (spec 7.7): its teardown takes the busy entry with the rest, and the
/// next entry of the call fails with BAD_STATE in x0 alone, with no long
/// call left. The mapping starts a portion below a bound of 2 MiB, so that
/// the first portion takes three tables and leaves a page of what the
/// call paid for tables: what the call paid and did not take goes back to
/// the target, whose shell goes with its quota whole, and the object and
/// the target leave their pools.
pub fn dying_target_ends_the_map(_: &Boot) -> Result<(), &'static str> {
    let (objects, processes) = (memory::in_use(), process::in_use());
    with_caller(|c| {
        let (h, m) = make_memory(c, LONG_PAGES)?;
        let (t, th) = target_of(c)?;
        let n = Call::MemMap.number();
        let args = [
            th.0,
            h.0,
            0,
            LONG_PAGES * PAGE_SIZE,
            (USER_VA + (2 << 20) - process::PORTION as usize * PAGE) as u64,
            Access::ReadWrite.raw(),
        ];
        let mut last = [0; 10];
        with_interrupt_pending(|| {
            c.call(n, &args);
            // SAFETY: the test holds a reference to the process.
            unsafe { process::end(t, ProcessState::Killed, CAUSE) };
            cleanup::drain();
            last = c.again(n);
            Ok(())
        })?;
        let mappings = memory::info(m).mappings;
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        let mut want = with_marks(&args);
        want[0] = Error::BadState.code();
        check(
            last == want && thread::long(c.thread).is_none(),
            "the call did not end with BAD_STATE alone",
        )?;
        check(mappings == 0, "the teardown of the target kept the entry")
    })?;
    check(
        memory::in_use() == objects && process::in_use() == processes,
        "the object or the target stayed",
    )
}

/// What `exec_mapping_syncs_the_instruction_cache` watches through the
/// test points code_synced and code_mapped (arch::cache,
/// process::maps): the frames made coherent so far, the frames whose
/// executable pages were mapped after that and before, and the calls that
/// made frames coherent, one a portion.
struct CodeWatch {
    on: bool,
    synced: [u64; 16],
    count: usize,
    mapped: usize,
    early: usize,
    calls: usize,
}

static CODE: Lock<CodeWatch> = Lock::new(CodeWatch {
    on: false,
    synced: [0; 16],
    count: 0,
    mapped: 0,
    early: 0,
    calls: 0,
});

/// The instruction cache was made coherent for `frames`
/// (testpoint::code_synced).
pub fn code_synced(frames: &[u64]) {
    let mut w = CODE.lock();
    if w.on {
        w.calls += 1;
        for &f in frames {
            if w.count < w.synced.len() {
                let i = w.count;
                w.synced[i] = f;
                w.count += 1;
            }
        }
    }
}

/// Descriptors that let a program execute `frames` were written
/// (testpoint::code_mapped): each frame counts as mapped after its
/// coherence or before it.
pub fn code_mapped(frames: &[u64]) {
    let mut w = CODE.lock();
    if w.on {
        for f in frames {
            if w.synced[..w.count].contains(f) {
                w.mapped += 1;
            } else {
                w.early += 1;
            }
        }
    }
}

/// Code runs from a page only after the instruction cache is coherent for
/// its frame (spec 7.4, [G18]): mem_map RX of an object of 12 pages, a
/// portion of process::EXEC_PORTION and one of 4, and mem_protect to RX of
/// a mapping of another object of 3 pages, one portion, make each frame
/// coherent before the descriptor of its page is written, once a portion.
/// QEMU has no caches, so only the test points show the order.
pub fn exec_mapping_syncs_the_instruction_cache(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), OWNER_RIGHTS)?;
        let (code, _) = make_memory(c, 12)?;
        let (data, _) = make_memory(c, 3)?;
        let protect = Call::MemProtect.number();
        let data_va = USER_VA + 16 * PAGE;
        *CODE.lock() = CodeWatch {
            on: true,
            synced: [0; 16],
            count: 0,
            mapped: 0,
            early: 0,
            calls: 0,
        };
        let result = map_whole(c, own, code, 12, USER_VA, Access::ReadExec)
            .and_then(|()| map_whole(c, own, data, 3, data_va, Access::ReadWrite))
            .and_then(|()| {
                let args = [own.0, data_va as u64, 3 * PAGE_SIZE, Access::ReadExec.raw()];
                c.succeeds(protect, &args, &[])
            });
        let watch = {
            let mut w = CODE.lock();
            w.on = false;
            (w.count, w.mapped, w.early, w.calls)
        };
        for h in [own, code, data] {
            c.close(h)?;
        }
        result?;
        check(
            watch == (15, 15, 0, 3),
            "a page became executable before its frame was coherent, or not a portion at a time",
        )
    })
}

/// The mappings of a process go after its ASID (spec 7.7): a process with
/// one mapping ends, and its portions run one at a time; its entry leaves
/// the table only once its space went with the ASID at the stage Space,
/// and at the stage Mappings.
pub fn mappings_go_after_the_asid(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let (h, m) = make_memory(c, 1)?;
        let (t, th) = target_of(c)?;
        let result = map_whole(c, th, h, 1, USER_VA, Access::Read).and_then(|()| {
            // SAFETY: the test holds a reference to the process.
            unsafe { process::end(t, ProcessState::Killed, CAUSE) };
            let mut order = Ok(());
            for _ in 0..64 {
                let stage = process::progress(t).0;
                cleanup::portion();
                if process::mappings(t) == 0 {
                    order = check(
                        stage == Stage::Mappings && !mapped(t, USER_VA),
                        "the mappings went before the space and its ASID",
                    );
                    break;
                }
            }
            order.and(check(
                memory::info(m).mappings == 0,
                "the teardown kept the mapping",
            ))
        });
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        result
    })
}

/// An unmapped page no longer translates (spec 7.4): a page of an object
/// mapped RW into the caller's process, whose space runs in TTBR0, reads
/// its pattern, which puts it in the TLB; mem_unmap takes it, neither EL0
/// nor the kernel translates it, and the tables hold nothing there. A page
/// of another object mapped at the same address shows through at once: a
/// TLB entry the unmap left would still show the first one, since QEMU
/// keeps its translations until a TLBI.
pub fn unmapped_page_no_longer_translates(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), OWNER_RIGHTS)?;
        let (first, a) = make_memory(c, 1)?;
        let (second, b) = make_memory(c, 1)?;
        for (m, pattern) in [(a, 0xC3), (b, 0xE5)] {
            let pa = memory::frame(m, 0);
            for i in 0..PAGE_SIZE / 8 {
                // SAFETY: the frame is the object's, which the test holds,
                // and the linear map reaches it.
                unsafe { ((LINEAR_BASE + (pa + i * 8) as usize) as *mut u64).write(pattern) };
            }
        }
        let result = map_whole(c, own, first, 1, USER_VA, Access::ReadWrite)
            .and_then(|()| check_unmap(c, own, second));
        for h in [own, first, second] {
            c.close(h)?;
        }
        result
    })
}

fn check_unmap(c: &Caller, own: Handle, second: Handle) -> Result<(), &'static str> {
    // SAFETY: the process is the test's, and nothing runs it.
    unsafe { (*c.process.as_ptr()).activate() };
    // The read brings the page into the TLB, which the unmap must drop.
    check(read_user(USER_VA) == 0xC3, "the page misses its contents")?;
    unmap_whole(c, own, 1, USER_VA)?;
    check(
        !translates(registers::at_s1e0r(USER_VA)) && !translates(registers::at_s1e1r(USER_VA)),
        "an unmapped page still translates",
    )?;
    check(
        !mapped(c.process, USER_VA),
        "the tables still hold an unmapped page",
    )?;
    // Another frame at the same address shows through at once.
    map_whole(c, own, second, 1, USER_VA, Access::ReadWrite)?;
    let seen = read_user(USER_VA);
    unmap_whole(c, own, 1, USER_VA)?;
    check(seen == 0xE5, "the TLB still holds the unmapped page")
}

/// The object over the boot image owns none of its frames (spec 13.1): an
/// object over the image that a caller pays for reports the image's size,
/// no page it owns and no mapping; once its handle closes and its portion
/// ran, the free frames, the caller's used memory and the objects in pools
/// are what they were, and the image still holds its bytes. An object made
/// and closed first leaves a free place in the caller's pool.
pub fn boot_image_frames_never_go(boot: &Boot) -> Result<(), &'static str> {
    let image = boot.info.initrd.ok_or("no boot image")?;
    let pages = (image.size / PAGE_SIZE) as usize;
    let words = |base: u64| {
        let mut sum = 0u64;
        for i in 0..image.size as usize / 8 {
            // SAFETY: the boot image lies in RAM the linear map covers, and
            // nothing writes to it.
            let w =
                unsafe { ((LINEAR_BASE + base as usize + 8 * i) as *const u64).read_volatile() };
            sum = sum.rotate_left(5) ^ w;
        }
        sum
    };
    let before = words(image.base);
    with_caller(|c| {
        let (h, _) = make_memory(c, 1)?;
        c.close(h)?;
        cleanup::drain();
        let objects = memory::in_use();
        let (free, used) = (phys::free_frames(), process::quota(c.process).used());
        let m = memory::create_boot(c.process, image.base, pages)
            .map_err(|_| "no object over the boot image")?;
        let h = c.insert(Object::Memory(m), abi::INIT_BOOT_IMAGE_RIGHTS);
        let info = memory::info(m);
        // SAFETY: the reference `create_boot` handed out goes; the handle,
        // if it went in, holds the object.
        unsafe { memory::release(m, CAUSE) };
        c.close(h?)?;
        cleanup::drain();
        check(
            info == MemoryInfo {
                size: image.size,
                pages: 0,
                mappings: 0,
            },
            "the object over the boot image does not report the image",
        )?;
        check(
            phys::free_frames() == free
                && process::quota(c.process).used() == used
                && memory::in_use() == objects,
            "the object over the boot image gave frames back or kept its place",
        )?;
        check(words(image.base) == before, "the boot image lost its bytes")
    })
}

/// Init's loader maps each part with its access (spec 13.3): the program
/// of the boot image, loaded into a new process, shows its code RX, its
/// read-only data R and its data RW, each page on a frame of a memory
/// object of its own, and a stack RW right under abi::INIT_STACK_TOP with
/// an unmapped guard page below; each part takes one mapping.
pub fn init_load_maps_each_part_with_its_access(boot: &Boot) -> Result<(), &'static str> {
    let program = crate::boot::init_program(boot);
    let p = process::create_root(QUOTA, LIMIT, CEILING).map_err(|_| "no process")?;
    let result = match crate::init::load(p, &program) {
        Ok(()) => loaded_parts(p, &program),
        Err(f) => {
            kprintln!(
                "{} of {:#x} bytes: {:?}, object made: {}",
                f.what,
                f.size,
                f.error,
                f.made
            );
            Err("init's program did not load")
        }
    };
    // SAFETY: the test's reference goes, and nothing uses it afterwards.
    unsafe { process::release(p, CAUSE) };
    cleanup::drain();
    result
}

fn loaded_parts(p: NonNull<Process>, program: &bootimg::Program<'_>) -> Result<(), &'static str> {
    let shows = |va: u64, attrs: Attrs| {
        process::translate(p, va as usize).is_some_and(|(pa, d)| d == page_descriptor(pa, attrs))
    };
    let mut parts = 1;
    for (part, attrs) in [
        (bootimg::Part::Code, Attrs::USER_TEXT),
        (bootimg::Part::Rodata, Attrs::USER_RODATA),
        (bootimg::Part::Data, Attrs::USER_DATA),
    ] {
        let segment = &program.segments[part as usize];
        if segment.mem_size == 0 {
            continue;
        }
        parts += 1;
        check(
            segment.pages().step_by(PAGE).all(|va| shows(va, attrs)),
            "a segment of init does not show with the access of its part",
        )?;
    }
    let top = abi::INIT_STACK_TOP;
    let bottom = top - u64::from(program.stack_size);
    check(
        (bottom..top)
            .step_by(PAGE)
            .all(|va| shows(va, Attrs::USER_DATA)),
        "init's stack is not RW",
    )?;
    check(
        process::translate(p, (bottom - PAGE_SIZE) as usize).is_none(),
        "init's stack has no guard page",
    )?;
    check(
        process::mappings(p) == parts,
        "a part of init did not take one mapping",
    )
}

// Interrupt bindings (spec 9). The tests make lines pending at the
// distributor by hand and take them as the way out of the kernel does:
// the lines they bind have no device behind them in QEMU `virt`.

/// The line most tests bind, and a second one.
const LINE: u32 = 40;
const OTHER_LINE: u32 = 41;
/// A line the tests bind edge-triggered, and one they bind
/// level-triggered, the PL031's.
const EDGE_LINE: u32 = 48;
const LEVEL_LINE: u32 = 34;
/// The label of the copy of the channel a binding goes through.
const IRQ_LABEL: u64 = 0x1A7;

/// Takes the interrupt of `line`, which the test made pending, and handles
/// it as the way out of the kernel does (interrupt::handle): the handler
/// ends it.
fn take_line(line: u32) -> Result<(), &'static str> {
    let ack = (0..1000)
        .find_map(|_| gic::acknowledge())
        .ok_or("the line's interrupt did not arrive")?;
    if ack.intid() != line {
        gic::end(ack);
        return Err("an interrupt of another line arrived");
    }
    crate::interrupt::handle(ack);
    Ok(())
}

/// The notification of an interrupt of a binding made through a handle
/// with `label`: bit 0, `count` deliveries.
fn interrupt_notice(label: u64, count: u32) -> [u64; 9] {
    let n = Notification {
        source: Source::Interrupt,
        label,
        bits: 1,
        count,
    };
    n.to_words()[..9].try_into().expect("x1-x9")
}

/// The binding behind the caller's handle `h`.
fn irq_of(c: &Caller, h: Handle) -> Result<NonNull<Irq>, &'static str> {
    // SAFETY: the caller's process is the test's.
    unsafe { c.process.as_ref() }
        .lookup(h, Rights::NONE, Object::irq)
        .map_err(|_| "the handle does not name a binding")
}

/// What IRQ reports for the caller's binding `b`.
fn irq_info_of(c: &Caller, b: Handle) -> Result<IrqInfo, &'static str> {
    let x = c.call(Call::ObjectInfo.number(), &[b.0, INFO_IRQ, 0]);
    if x[0] != 0 {
        return Err("object_info IRQ failed");
    }
    Ok(IrqInfo::from_words([x[1], x[2], x[3]]))
}

/// Runs `body` with a caller that holds the system resource with DEVICE,
/// a channel at 10 with a copy of it with NOTIFY and IRQ_LABEL, and a
/// binding of `line` through the copy, whose slot has priority 20; closes
/// the handles afterwards and runs the cleanup queue dry. The live
/// bindings are as many as before.
fn with_binding(
    line: u32,
    edge: bool,
    body: impl FnOnce(&Caller, Handle, Handle) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let bindings = irq::in_use();
    with_caller(|c| {
        let r = c.insert(Object::Resource, Rights::DEVICE)?;
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let copy = c.created(
            Call::HandleDuplicate.number(),
            &[h.0, Rights::NOTIFY.0.into(), IRQ_LABEL, 10],
        )?;
        let flags = if edge { TRIGGER_EDGE } else { 0 };
        let made = c.created(
            Call::IrqBind.number(),
            &[r.0, line.into(), copy.0, 20, flags],
        );
        let result = made.and_then(|b| {
            let result = body(c, h, b);
            // A test may close the binding itself.
            let _ = process::close_handle(c.process, b, CAUSE);
            result
        });
        for handle in [copy, h, r] {
            // The test may have closed the channel.
            let _ = process::close_handle(c.process, handle, CAUSE);
        }
        cleanup::drain();
        result
    })?;
    check(
        irq::in_use() == bindings,
        "a binding of the test stayed in its pool",
    )
}

/// An interrupt of a bound line (spec 9): the handler masks the line at the
/// distributor (GICD_ICENABLER), posts bit 0 into the binding's slot and
/// ends the interrupt, so the line is neither enabled nor active
/// afterwards; receive takes one notification of an interrupt with the
/// label of the handle the binding went through, bit 0, one delivery, and
/// IRQ reports the line masked.
pub fn delivery_masks_posts_and_ends(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, false, |c, h, b| {
        check(gic::is_enabled(LINE), "a new binding left its line masked")?;
        gic::set_pending(LINE);
        take_line(LINE)?;
        check(
            !gic::is_enabled(LINE) && !gic::is_active(LINE),
            "the delivery left the line enabled or active",
        )?;
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &interrupt_notice(IRQ_LABEL, 1),
        )?;
        check(label_of(c) == IRQ_LABEL, "the notification lacks the label")?;
        check(
            irq_info_of(c, b)?.masked,
            "IRQ does not report the line masked",
        )?;
        nothing_pending("an interrupt is pending after the delivery")
    })
}

/// irq_ack opens a line a delivery masked (spec 9): the line is enabled
/// again and IRQ reports it open; irq_ack of an open line returns 0 and
/// leaves it open.
pub fn irq_ack_unmasks_the_line(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, false, |c, h, b| {
        gic::set_pending(LINE);
        take_line(LINE)?;
        c.succeeds(Call::IrqAck.number(), &[b.0], &[])?;
        check(gic::is_enabled(LINE), "irq_ack left the line masked")?;
        check(
            !irq_info_of(c, b)?.masked,
            "IRQ reports the line masked after irq_ack",
        )?;
        c.succeeds(Call::IrqAck.number(), &[b.0], &[])?;
        check(gic::is_enabled(LINE), "irq_ack of an open line masked it")?;
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &interrupt_notice(IRQ_LABEL, 1),
        )
    })
}

/// A masked line waits for irq_ack (spec 9): with the line masked, a new
/// interrupt stays pending at the distributor and reaches no CPU; one that
/// reached the handler before the mask did, which the test makes by
/// opening the line by hand, posts nothing. Receive then takes one
/// delivery. After irq_ack the interrupt that waited comes: a second
/// notification.
pub fn masked_line_waits_for_irq_ack(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, true, |c, h, b| {
        gic::set_pending(LINE);
        take_line(LINE)?;
        gic::set_pending(LINE);
        nothing_pending("a masked line reached the CPU")?;
        gic::unmask(LINE);
        let late = take_line(LINE);
        gic::mask(LINE);
        late?;
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &interrupt_notice(IRQ_LABEL, 1),
        )?;
        gic::set_pending(LINE);
        c.succeeds(Call::IrqAck.number(), &[b.0], &[])?;
        take_line(LINE)?;
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &interrupt_notice(IRQ_LABEL, 1),
        )
    })
}

/// A closed channel keeps its binding's line masked (spec 9): the
/// delivery posts nothing and masks the line, irq_ack fails with
/// PEER_CLOSED, and the line stays masked.
pub fn closed_channel_keeps_the_line_masked(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, false, |c, h, b| {
        // The last handle with RECEIVE goes: the channel closes (spec 6.8).
        c.close(h)?;
        gic::set_pending(LINE);
        take_line(LINE)?;
        check(
            !gic::is_enabled(LINE),
            "a delivery into a closed channel left the line open",
        )?;
        c.fails(Call::IrqAck.number(), &[b.0], Error::PeerClosed)?;
        check(
            !gic::is_enabled(LINE) && irq_info_of(c, b)?.masked,
            "irq_ack on a closed channel opened the line",
        )
    })
}

/// The last handle to a binding masks its line and frees it at once (spec
/// 7.7, 9): before the cleanup queue runs, the line is masked, no binding
/// holds it and irq_bind of it succeeds; the portion gives the channel's
/// slot back.
pub fn released_binding_masks_and_frees_its_line(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, false, |c, h, b| {
        let ch = channel_of(c, h)?;
        let sources = channel::sources(ch);
        c.close(b)?;
        check(
            !gic::is_enabled(LINE) && irq::bound(LINE).is_none(),
            "the last handle left the line open or bound",
        )?;
        check(
            channel::sources(ch) == sources,
            "the binding gave its slot back before its portion",
        )?;
        let r = c.insert(Object::Resource, Rights::DEVICE)?;
        let again = c.created(Call::IrqBind.number(), &[r.0, LINE.into(), h.0, 20, 0]);
        if let Ok(again) = again {
            c.close(again)?;
        }
        c.close(r)?;
        again?;
        cleanup::drain();
        check(
            channel::sources(ch) == sources - 1,
            "the portion of the binding did not give the channel's slot back",
        )
    })
}

/// A notification in the channel's queue does not hold the line (spec
/// 9, 13.4): with the slot of a delivery queued, the last handle to the
/// binding masks the line and frees it, and irq_bind of it succeeds while
/// the slot still holds the binding; receive then takes the notification,
/// and the binding goes.
pub fn queued_notice_does_not_hold_the_line(_: &Boot) -> Result<(), &'static str> {
    with_binding(LINE, false, |c, h, b| {
        gic::set_pending(LINE);
        take_line(LINE)?;
        let bindings = irq::in_use();
        c.close(b)?;
        check(
            !gic::is_enabled(LINE) && irq::bound(LINE).is_none(),
            "a queued notification kept the line open or bound",
        )?;
        let r = c.insert(Object::Resource, Rights::DEVICE)?;
        let again = c.created(Call::IrqBind.number(), &[r.0, LINE.into(), h.0, 20, 0]);
        if let Ok(again) = again {
            c.close(again)?;
        }
        c.close(r)?;
        again?;
        check(
            irq::in_use() == bindings + 1,
            "the binding went while its slot was queued",
        )?;
        c.succeeds(
            Call::Receive.number(),
            &[h.0, NO_WAIT],
            &interrupt_notice(IRQ_LABEL, 1),
        )
    })
}

/// An interrupt of a line no binding holds is masked and ended (spec 9):
/// the kernel stays up, and the line is neither enabled nor active.
pub fn stray_line_is_masked_and_ended(_: &Boot) -> Result<(), &'static str> {
    check(irq::bound(OTHER_LINE).is_none(), "the line has a binding")?;
    gic::unmask(OTHER_LINE);
    gic::set_pending(OTHER_LINE);
    take_line(OTHER_LINE)?;
    check(
        !gic::is_enabled(OTHER_LINE) && !gic::is_active(OTHER_LINE),
        "a stray line stayed enabled or active",
    )?;
    nothing_pending("an interrupt is pending after the stray one")
}

/// irq_bind writes the kind of trigger to GICD_ICFGR each time (spec 9):
/// bit 2n + 1 of the line is set for TRIGGER_EDGE and clear without it,
/// also when the line was edge-triggered before.
pub fn edge_flag_sets_the_trigger(_: &Boot) -> Result<(), &'static str> {
    with_binding(EDGE_LINE, true, |_, _, _| {
        check(
            gic::is_edge(EDGE_LINE),
            "an edge-triggered binding left the line level-triggered",
        )
    })?;
    with_binding(EDGE_LINE, false, |_, _, _| {
        check(
            !gic::is_edge(EDGE_LINE),
            "a level-triggered binding left the line edge-triggered",
        )
    })?;
    with_binding(LEVEL_LINE, false, |_, _, _| {
        check(
            !gic::is_edge(LEVEL_LINE),
            "a level-triggered binding made the line edge-triggered",
        )
    })
}

/// irq_bind stops at the caller's limits (spec 7.8, 9, 11): with every
/// slot of the channel taken it fails with LIMIT_REACHED before the quota,
/// with the caller's quota spent with NO_MEMORY for a page of its pool of
/// bindings, and with its table full with LIMIT_REACHED, nothing made; a
/// priority above the caller's ceiling fails with ACCESS_DENIED. A good
/// call makes a binding the caller pays for, through a channel of another
/// process. A binding made whose handle then finds no page for a new chunk
/// of the table fails with NO_MEMORY, and its line is masked and free
/// again at once.
pub fn irq_bind_checks_the_callers_limits(_: &Boot) -> Result<(), &'static str> {
    let bindings = irq::in_use();
    let c = Caller::with_ceiling(30)?;
    let result = irq_bind_cases(&c);
    c.release();
    result?;
    let c = Caller::with_limit(2 * CHUNK as u32, 30)?;
    let result = bind_without_its_handle(&c);
    c.release();
    result?;
    check(
        irq::in_use() == bindings,
        "a binding of the test stayed in its pool",
    )
}

fn irq_bind_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::IrqBind.number();
    let r = c.insert(Object::Resource, Rights::DEVICE)?;
    // First, while the caller's pool of bindings has no page.
    let full = c.created(Call::CreateChannel.number(), &[10])?;
    let refused = fill_slots(c, full).and_then(|()| {
        with_used_quota(c, || {
            c.fails(n, &[r.0, LINE.into(), full.0, 20, 0], Error::LimitReached)
        })
    });
    c.close(full)?;
    cleanup::drain();
    refused?;
    let owner = Caller::new()?;
    let result = (|| {
        let theirs = owner.created(Call::CreateChannel.number(), &[10])?;
        let ch = channel_of(&owner, theirs)?;
        let h = c.insert(Object::Channel(ch), Rights::NOTIFY)?;
        let args = [r.0, LINE.into(), h.0, 20, 0];
        c.fails(n, &[r.0, LINE.into(), h.0, 31, 0], Error::AccessDenied)?;
        let bindings = irq::in_use();
        with_used_quota(c, || {
            c.fails(n, &args, Error::NoMemory)?;
            with_full_table(c, n, &args)
        })?;
        check(
            irq::in_use() == bindings && irq::bound(LINE).is_none(),
            "a binding that did not fit stayed",
        )?;
        let used = process::quota(c.process).used();
        let b = c.created(n, &[r.0, LINE.into(), h.0, 30, 0])?;
        let paid = irq_of(c, b).map(|i| {
            irq::payer(i) == c.process && process::quota(c.process).used() == used + PAGE_SIZE
        });
        c.close(b)?;
        c.close(h)?;
        check(
            paid?,
            "the caller did not pay a page of its pool for the binding",
        )
    })();
    owner.release();
    result
}

/// irq_bind whose binding is made, and whose handle then takes a new
/// chunk of the caller's table with no quota left for its page.
fn bind_without_its_handle(c: &Caller) -> Result<(), &'static str> {
    let r = c.insert(Object::Resource, Rights::DEVICE)?;
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    // The first chunk of the table fills: the next handle takes a page.
    for _ in 2..CHUNK {
        c.insert(Object::Resource, Rights::NONE)?;
    }
    let args = [r.0, LINE.into(), h.0, 20, 0];
    with_quota_left(c, PAGE_SIZE, || {
        c.fails(Call::IrqBind.number(), &args, Error::NoMemory)
    })?;
    check(
        !gic::is_enabled(LINE) && irq::bound(LINE).is_none(),
        "a binding whose handle did not go in left its line open or bound",
    )
}

// The longest portions of the long calls of memory objects (spec 7.7,
// 15.3), in their worst cases, under -icount.

/// Pages of the objects whose first entry of mem_create takes the node of
/// nodes of their list besides a leaf (kcore::pagelist): more than a leaf
/// holds.
#[cfg(feature = "icount")]
const DEEP_PAGES: u64 = 520;

/// The span of a table of level 1: a range across a bound of it with no
/// table on either side takes a table of each level on both (spec 7.5,
/// kcore::paging::tables_bound).
#[cfg(feature = "icount")]
const REGION: usize = 512 * GIB as usize;

/// A block of kcore::frames::MAX_ORDER frames: a frame alone in a free one
/// merges MAX_ORDER times as it goes back.
#[cfg(feature = "icount")]
const BLOCK: u64 = PAGE_SIZE << kcore::frames::MAX_ORDER;

/// The blocks `Apart` sets apart: one for each frame of the memory object
/// whose last portion `release_ticks` measures, its pages and the node of
/// their list.
#[cfg(feature = "icount")]
const APART: usize = kcore::pagelist::RELEASE_STEP;

/// The frame allocator taken apart for the costliest frees (spec 7.7):
/// every free block goes to the test, in a chain through the first words
/// of the blocks, but APART blocks of MAX_ORDER, which the allocator gets
/// back frame by frame; the first frame of each is then the allocator's
/// only free frame, so that the next APART frames taken are alone in
/// their blocks once `spread` gives the rest back.
#[cfg(feature = "icount")]
struct Apart {
    chain: u64,
    blocks: [u64; APART],
}

#[cfg(feature = "icount")]
impl Apart {
    fn take() -> Result<Apart, &'static str> {
        let mut apart = Apart {
            chain: 0,
            blocks: [0; APART],
        };
        let mut kept = 0;
        for order in (0..=kcore::frames::MAX_ORDER).rev() {
            while let Some(pa) = frames_alloc(order) {
                if order == kcore::frames::MAX_ORDER && kept < APART {
                    apart.blocks[kept] = pa;
                    kept += 1;
                } else {
                    apart.link(pa, order);
                }
            }
        }
        for &b in &apart.blocks[..kept] {
            frames_free(b, kcore::frames::MAX_ORDER);
        }
        if kept < APART {
            apart.rejoin();
            return Err("too few free blocks of the highest order");
        }
        for b in &mut apart.blocks {
            let first = frames_alloc(0).ok_or("a frame of a block went missing")?;
            *b = first;
            let whole = first.is_multiple_of(BLOCK)
                && (1..BLOCK / PAGE_SIZE).all(|k| frames_alloc(0) == Some(first + k * PAGE_SIZE));
            if !whole {
                return Err("a block did not give its frames in order");
            }
        }
        for &b in &apart.blocks {
            frames_free(b, 0);
        }
        Ok(apart)
    }

    /// Puts block `pa` of `order` at the head of the chain.
    fn link(&mut self, pa: u64, order: u8) {
        let word = (LINEAR_BASE + pa as usize) as *mut u64;
        // SAFETY: the block is the test's, taken from the allocator, and
        // the linear map reaches it.
        unsafe {
            word.write_volatile(self.chain);
            word.add(1).write_volatile(order.into());
        }
        self.chain = pa;
    }

    /// Gives the frames of the blocks but their first back.
    fn spread(&self) {
        for &b in &self.blocks {
            for k in 1..BLOCK / PAGE_SIZE {
                frames_free(b + k * PAGE_SIZE, 0);
            }
        }
    }

    /// Gives every block of the chain back.
    fn rejoin(self) {
        let mut next = self.chain;
        while next != 0 {
            let word = (LINEAR_BASE + next as usize) as *const u64;
            // SAFETY: as in `link`.
            let (after, order) = unsafe { (word.read_volatile(), word.add(1).read_volatile()) };
            frames_free(next, order as u8);
            next = after;
        }
    }
}

/// A block of `order` from the frame allocator, if there is one (spec
/// 7.1).
#[cfg(feature = "icount")]
fn frames_alloc(order: u8) -> Option<u64> {
    phys::FRAMES.lock().as_mut().expect("frames").alloc(order)
}

/// Gives block `pa` of `order` back to the frame allocator (spec 7.1).
#[cfg(feature = "icount")]
fn frames_free(pa: u64, order: u8) {
    phys::FRAMES
        .lock()
        .as_mut()
        .expect("frames")
        .free(pa, order)
}

/// The portions of the long calls of memory objects in their worst cases,
/// in counter ticks, which count instructions under -icount (spec 7.7,
/// 15.3). With an interrupt pending all along each entry of a call takes
/// one portion, and an entry counts from the kernel's dispatch of the call
/// to its end:
/// - create: the entries of mem_create of DEEP_PAGES pages in a new
///   process, the first with a chunk of its table, a page of its pool of
///   memory objects and the node of nodes;
/// - map, map_exec: the entries of mem_map but the first, RW and RX, whose
///   portion crosses a bound of REGION and takes three tables;
/// - protect, protect_exec, unmap: the entries of mem_protect to R and to
///   RX and of mem_unmap of a mapping of 64 pages, among 64 mappings of a
///   process with 64 threads and an ASID, which takes a TLBI a page;
/// - release: the portion of cleanup of a memory object that gives back its
///   last pages, the node of their list and the object's place and budget,
///   whose frames are each alone in their free block of MAX_ORDER frames,
///   and merge up to it as they go back (`Apart`);
/// - first_map: the first entry of mem_map RX of 8 pages across a bound of
///   REGION with no table on either side, six tables: the 64th mapping of
///   that process, and the first one of a new process, with the block of
///   its table.
///
/// The test prints them in one line, `memory portions ticks: create=...
/// map=... map_exec=... unmap=... protect=... protect_exec=... release=...
/// first_map=...`, which xtask shows; no number fails it (spec 15.3).
#[cfg(feature = "icount")]
pub fn memory_portions_are_measured(_: &Boot) -> Result<(), &'static str> {
    let objects = memory::in_use();
    let memory = phys::free_frames() + pages::taken() as u64;
    let create = [0, CHUNK].into_iter().try_fold(0, |most, fill| {
        create_ticks(fill).map(|ticks| most.max(ticks))
    })?;
    let mut changes = [0; 6];
    with_caller(|c| changes_ticks(c, &mut changes))?;
    let fresh = with_caller(|c| {
        let (h, _) = make_memory(c, u64::from(process::EXEC_PORTION))?;
        let (t, th) = target_of(c)?;
        let ticks = first_exec_ticks(c, th, h);
        c.close(th)?;
        c.close(h)?;
        release_target(t);
        ticks
    })?;
    let release = with_caller(release_ticks)?;
    let [map, map_exec, unmap, protect, protect_exec, crowded] = changes;
    kprintln!(
        "memory portions ticks: create={create} map={map} map_exec={map_exec} unmap={unmap} protect={protect} protect_exec={protect_exec} release={release} first_map={}",
        crowded.max(fresh)
    );
    check(
        memory::in_use() == objects && phys::free_frames() + pages::taken() as u64 == memory,
        "an object or a frame of the measurements stayed",
    )
}

/// The longest entry of mem_create of DEEP_PAGES pages by a new process
/// whose table holds `fill` handles: its first entry makes a chunk of the
/// table, whose page the pool of blocks takes, and a page of the pool of
/// memory objects, before its portion takes the node of nodes, a leaf and
/// memory::CREATE_PORTION frames.
#[cfg(feature = "icount")]
fn create_ticks(fill: usize) -> Result<u64, &'static str> {
    let process = process::create_root(QUOTA, 2 * CHUNK as u32, CEILING);
    let process = process.map_err(|_| "no process")?;
    let c = match thread::create(process, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
        Ok(thread) => Caller { process, thread },
        Err(_) => {
            // SAFETY: the process is the test's, and nothing uses it afterwards.
            unsafe { process::release(process, CAUSE) };
            return Err("no thread");
        }
    };
    let ticks = (0..fill)
        .try_for_each(|_| c.insert(Object::Resource, Rights::NONE).map(|_| ()))
        .and_then(|()| {
            let n = Call::MemCreate.number();
            let (first, rest, got) = timed_entries(&c, n, &[DEEP_PAGES * PAGE_SIZE, 0])?;
            c.close(Handle(got[1]))?;
            Ok(first.max(rest))
        });
    c.release();
    ticks
}

/// Makes call `number` with `args`, then its next entries until it ends,
/// with an interrupt pending all along: the ticks of the first entry and
/// of the longest of the others, and x0-x9 at the end.
#[cfg(feature = "icount")]
fn timed_entries(
    c: &Caller,
    number: u16,
    args: &[u64],
) -> Result<(u64, u64, [u64; 10]), &'static str> {
    let (mut first, mut rest, mut got) = (0, 0, [0; 10]);
    with_interrupt_pending(|| {
        let start = timer::now();
        got = c.call(number, args);
        first = timer::now() - start;
        while thread::long(c.thread).is_some() {
            let start = timer::now();
            got = c.again(number);
            rest = rest.max(timer::now() - start);
        }
        Ok(())
    })?;
    check(got[0] == 0, "a measured call failed")?;
    Ok((first, rest, got))
}

/// The first entry of mem_map by `c` of object `h`, of process::EXEC_PORTION
/// pages, RX, across the first bound of REGION of the process behind
/// `target`, which has no table there; the mapping goes again.
#[cfg(feature = "icount")]
fn first_exec_ticks(c: &Caller, target: Handle, h: Handle) -> Result<u64, &'static str> {
    let pages = u64::from(process::EXEC_PORTION);
    let va = REGION - (pages / 2) as usize * PAGE;
    let args = [
        target.0,
        h.0,
        0,
        pages * PAGE_SIZE,
        va as u64,
        Access::ReadExec.raw(),
    ];
    let (first, _, _) = timed_entries(c, Call::MemMap.number(), &args)?;
    unmap_whole(c, target, pages, va)?;
    Ok(first)
}

/// Into `ticks`, for a process with abi::MAX_THREADS threads with their
/// buffers, 63 mappings and an ASID: map, map_exec, unmap, protect,
/// protect_exec, and the first entry of its 64th mapping (`first_exec_ticks`).
/// Its threads, its mappings and its own tables lie past 4 REGIONs, so the
/// regions below them have no table.
#[cfg(feature = "icount")]
fn changes_ticks(c: &Caller, ticks: &mut [u64; 6]) -> Result<(), &'static str> {
    let (h, _) = make_memory(c, 64)?;
    let (t, th) = target_of(c)?;
    let mut threads = [None; abi::MAX_THREADS as usize];
    let crowded = crowd(t, &mut threads).and_then(|()| {
        // SAFETY: the process is the test's, and nothing runs it.
        unsafe { (*t.as_ptr()).activate() };
        ticks[5] = first_exec_ticks(c, th, h)?;
        let map = |pages: u64, va: usize, access: Access| {
            let args = [th.0, h.0, 0, pages * PAGE_SIZE, va as u64, access.raw()];
            timed_entries(c, Call::MemMap.number(), &args).map(|(_, rest, _)| rest)
        };
        let change = |n: Call, va: usize, access: u64| {
            let args = [th.0, va as u64, 64 * PAGE_SIZE, access];
            timed_entries(c, n.number(), &args).map(|(first, rest, _)| first.max(rest))
        };
        // Its second portion of 8 pages crosses the bound of 2 REGIONs.
        let exec = 2 * REGION - 12 * PAGE;
        ticks[1] = map(24, exec, Access::ReadExec)?;
        unmap_whole(c, th, 24, exec)?;
        // Its second portion of 32 pages crosses the bound of 3 REGIONs.
        let va = 3 * REGION - 48 * PAGE;
        ticks[0] = map(64, va, Access::ReadWrite)?;
        ticks[3] = change(Call::MemProtect, va, Access::Read.raw())?;
        ticks[4] = change(Call::MemProtect, va, Access::ReadExec.raw())?;
        ticks[2] = change(Call::MemUnmap, va, 0)?;
        Ok(())
    });
    for t in threads.into_iter().flatten() {
        // SAFETY: the test's reference goes; the thread never ran.
        unsafe { thread::release(t, CAUSE) };
    }
    c.close(th)?;
    c.close(h)?;
    release_target(t);
    crowded
}

/// abi::MAX_THREADS threads of `t` with their buffers, which `threads`
/// holds, and 63 mappings of a page of an object `t` pays for, all past 4
/// REGIONs.
#[cfg(feature = "icount")]
fn crowd(
    t: NonNull<Process>,
    threads: &mut [Option<NonNull<Thread>>; abi::MAX_THREADS as usize],
) -> Result<(), &'static str> {
    let far = 4 * REGION;
    for (i, slot) in threads.iter_mut().enumerate() {
        let made = thread::create(t, USER_VA, USER_VA, 0, 10, Policy::Fifo);
        *slot = Some(made.map_err(|_| "no thread")?);
        let buffer = thread::give_buffer(slot.expect("the thread"), far + i * PAGE);
        buffer.map_err(|_| "no buffer")?;
    }
    let single = memory::create_whole(t, 1).map_err(|_| "no memory object");
    single.and_then(|one| {
        let mapped = (0..abi::MAX_MAPPINGS as usize - 1).try_for_each(|i| {
            let va = far + (1 << 20) + i * PAGE;
            process::map_whole(t, one, va, Access::Read).map_err(|_| "a page did not map")
        });
        // SAFETY: the reference `create_whole` handed out goes; the
        // mappings hold the object.
        unsafe { memory::release(one, CAUSE) };
        mapped
    })
}

/// The portion of cleanup of a memory object of RELEASE_STEP - 1 pages,
/// which gives back the last pages, the node of their list and the
/// object's place and budget, whose frames each merge up to MAX_ORDER as
/// they go back (`Apart`), in ticks. An object made and closed first
/// leaves a free place in the pool of `c`, which then takes no frame for
/// it.
#[cfg(feature = "icount")]
fn release_ticks(c: &Caller) -> Result<u64, &'static str> {
    let (h, _) = make_memory(c, 1)?;
    c.close(h)?;
    cleanup::drain();
    let apart = Apart::take()?;
    let pages = kcore::pagelist::RELEASE_STEP - 1;
    let made = make_memory(c, pages as u64);
    apart.spread();
    let ticks = made.and_then(|(h, m)| {
        let alone = (0..pages).all(|i| memory::frame(m, i).is_multiple_of(BLOCK));
        c.close(h)?;
        let start = timer::now();
        cleanup::portion();
        let ticks = timer::now() - start;
        cleanup::drain();
        check(alone, "a frame of the object is not alone in its block")?;
        Ok(ticks)
    });
    apart.rejoin();
    ticks
}

/// The level of the heap of `timer_firing_is_measured`, its payers, and
/// the receivers its firing wakes, one a timer.
#[cfg(feature = "icount")]
const FIRE_LEVEL: u8 = 10;
#[cfg(feature = "icount")]
const FIRE_PAYERS: usize = 64;
#[cfg(feature = "icount")]
const WOKEN: usize = kcore::timer::FIRE_PORTION;

/// The timers of programs in their worst cases under -icount (spec 10,
/// 15.3), in ticks:
/// - interrupt: the timers' part of the kernel's timer interrupt
///   (timer::expire) with the top of every level of 1-63 expired, which
///   queues 63 firings;
/// - fire: the portion of cleanup of the firing of FIRE_LEVEL, whose heap
///   holds 4 096 timers of FIRE_PAYERS payers: it takes FIRE_PORTION
///   expired ones off a heap of depth 12, and each wakes a receiver that
///   waits in a channel of its own;
/// - set: timer_set of the top of that heap, among 63 levels with timers
///   and none pending, to a deadline before every other: it leaves the
///   root, the walk of the levels follows, and it climbs back to the root.
///
/// The test prints them in one line, `timer portions ticks: interrupt=...
/// fire=... set=...`, which xtask shows; no number fails it (spec 15.3).
#[cfg(feature = "icount")]
pub fn timer_firing_is_measured(_: &Boot) -> Result<(), &'static str> {
    let counts = (
        timers::in_use(),
        channel::in_use(),
        thread::in_use(),
        process::in_use(),
    );
    let ticks = with_caller(|c| {
        let owner = process::create_root(QUOTA, 128, CEILING).map_err(|_| "no process");
        let ticks = owner.and_then(|owner| {
            let ticks = firing_ticks(c, owner);
            // SAFETY: the test's reference goes; the handles went with it.
            unsafe { process::release(owner, CAUSE) };
            ticks
        });
        cleanup::drain();
        ticks
    })?;
    let [interrupt, fire, set] = ticks;
    kprintln!("timer portions ticks: interrupt={interrupt} fire={fire} set={set}");
    check(
        (
            timers::in_use(),
            channel::in_use(),
            thread::in_use(),
            process::in_use(),
        ) == counts,
        "a timer, a channel, a thread or a process of the measurements stayed",
    )
}

/// The three counts of `timer_firing_is_measured`: `owner` holds the
/// channels, their receivers and the timers of levels 1-63, with the
/// handles that keep them; each payer holds its timers.
#[cfg(feature = "icount")]
fn firing_ticks(c: &Caller, owner: NonNull<Process>) -> Result<[u64; 3], &'static str> {
    let mut receivers = [None; WOKEN];
    let mut payers = [None; FIRE_PAYERS];
    let ticks = heap_ticks(c, owner, &mut receivers, &mut payers);
    for t in receivers.into_iter().flatten() {
        // SAFETY: the test's reference goes, and the kernel's first: the
        // thread leaves the scheduler.
        unsafe {
            sched::exit(t, CAUSE);
            thread::release(t, CAUSE);
        }
    }
    for p in payers.into_iter().flatten() {
        // SAFETY: the test's reference goes; its handles hold its timers.
        unsafe { process::release(p, CAUSE) };
    }
    ticks
}

/// A channel of `owner` at FIRE_LEVEL with a handle with RECEIVE in its
/// table, which holds it.
#[cfg(feature = "icount")]
fn owned_channel(owner: NonNull<Process>) -> Result<NonNull<Channel>, &'static str> {
    let c = channel::create(owner, FIRE_LEVEL).map_err(|_| "no channel")?;
    let h = process::insert_handle(owner, Object::Channel(c), Rights::RECEIVE);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, CAUSE) };
    h.map(|_| c).map_err(|_| "a handle did not go in")
}

/// A timer of `payer` on `ch` at `level`, armed for `deadline` in ticks,
/// with a handle in the table of `payer`, which holds it.
#[cfg(feature = "icount")]
fn held_timer(
    payer: NonNull<Process>,
    ch: NonNull<Channel>,
    level: u8,
    deadline: u64,
) -> Result<NonNull<Timer>, &'static str> {
    let t = timers::create(payer, ch, 0, level).map_err(|_| "no timer")?;
    let armed = timers::set(t, deadline, CAUSE);
    let h = process::insert_handle(payer, Object::Timer(t), OWNER_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the timer.
    unsafe { timers::release(t, CAUSE) };
    armed.map_err(|_| "a timer was not armed")?;
    h.map(|_| t).map_err(|_| "a handle did not go in")
}

/// A new thread of `owner` waits in receive on `ch`: it starts, runs as
/// far as the scheduler knows, and its receive finds nothing.
#[cfg(feature = "icount")]
fn waiting(owner: NonNull<Process>, ch: NonNull<Channel>) -> Result<NonNull<Thread>, &'static str> {
    let t = thread::create(owner, USER_VA, USER_VA, 0, 5, Policy::Fifo).map_err(|_| "no thread")?;
    thread::start(t).map_err(|_| "a thread did not start")?;
    // SAFETY: the scheduler's threads are alive.
    let picked = sched::locked(|k| unsafe { k.s.pick(timer::now(), None) });
    check(
        matches!(picked, kcore::sched::Decision::Run(r) if r == t),
        "the new thread did not run",
    )?;
    channel::receive(t, ch, true).map_err(|_| "the receiver did not wait")?;
    Ok(t)
}

/// Builds what `timer_firing_is_measured` measures and measures it; the
/// receivers and the payers go into `receivers` and `payers` for the
/// caller to let go.
#[cfg(feature = "icount")]
fn heap_ticks(
    c: &Caller,
    owner: NonNull<Process>,
    receivers: &mut [Option<NonNull<Thread>>; WOKEN],
    payers: &mut [Option<NonNull<Process>>; FIRE_PAYERS],
) -> Result<[u64; 3], &'static str> {
    let mut channels = [None; WOKEN];
    for (ch, r) in channels.iter_mut().zip(receivers.iter_mut()) {
        let made = owned_channel(owner)?;
        *ch = Some(made);
        *r = Some(waiting(owner, made)?);
    }
    let channels = channels.map(|ch| ch.expect("a channel"));
    // The later timers of the heap by the order they go in, so that a
    // timer that leaves the root takes the last node down to a leaf.
    let far = timer::now() + 1_000_000_000;
    let mut early = [None; WOKEN];
    let mut top = None;
    for (i, payer) in payers.iter_mut().enumerate() {
        let p = process::create_root(QUOTA, 128, CEILING).map_err(|_| "no payer")?;
        *payer = Some(p);
        for j in 0..abi::MAX_TIMERS as usize {
            let n = i * abi::MAX_TIMERS as usize + j;
            let t = held_timer(p, channels[n % WOKEN], FIRE_LEVEL, far + n as u64)?;
            match n {
                n if n < WOKEN => early[n] = Some(t),
                n if n == WOKEN => top = Some(t),
                _ => {}
            }
        }
    }
    let lc = owned_channel(owner)?;
    let mut levels = [None; kcore::timer::LEVELS];
    for (l, t) in levels.iter_mut().enumerate() {
        *t = Some(held_timer(owner, lc, l as u8 + 1, 2 * far + l as u64)?);
    }
    let top = top.expect("the top of the heap");
    let h = c.insert(Object::Timer(top), OWNER_RIGHTS)?;
    let before = timer::clock().ticks_to_ns(far / 2);
    let start = timer::now();
    c.succeeds(Call::TimerSet.number(), &[h.0, before], &[])?;
    let set = timer::now() - start;
    c.close(h)?;
    // Every level expires, and the heap's receivers' timers first of all.
    let at = timer::now() + 2_000_000;
    for (n, t) in early.into_iter().flatten().enumerate() {
        timers::set(t, at + n as u64, CAUSE).map_err(|_| "a timer was not armed")?;
    }
    for (l, t) in levels.into_iter().flatten().enumerate() {
        timers::set(t, at + 100 + l as u64, CAUSE).map_err(|_| "a timer was not armed")?;
    }
    while timer::now() <= at + 200 {}
    let queued = cleanup::len();
    let start = timer::now();
    timers::expire(timer::now());
    let interrupt = timer::now() - start;
    check(
        cleanup::len() == queued + kcore::timer::LEVELS as u64,
        "the interrupt did not queue the firing of every level",
    )?;
    while cleanup::top().is_some_and(|l| l > FIRE_LEVEL) {
        cleanup::portion();
    }
    let start = timer::now();
    cleanup::portion();
    let fire = timer::now() - start;
    // SAFETY: the receivers are alive; only their states are read.
    let woke = receivers
        .iter()
        .flatten()
        .all(|t| unsafe { t.as_ref() }.sched.state() == State::Ready);
    cleanup::drain();
    check(woke, "a receiver of the heap's timers did not wake")?;
    Ok([interrupt, fire, set])
}
