// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests of the system calls (spec 11, 12). The kernel makes each
//! call for a thread that never runs, as if the thread had made it, and
//! checks every register the call may write: on an error only x0 changes,
//! on success x0 is 0 and the values follow in x1 and up. The same calls
//! from EL0 are in `el0`.

use super::{CAUSE, CHILD_QUOTA, QUOTA, check};
use crate::arch::timer;
use crate::boot::Boot;
use crate::channel::{self, Channel};
use crate::cleanup;
use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process::{self, Process};
use crate::session::{self, Session};
use crate::thread::{self, Policy, Thread};
use crate::timer::{self as timers, Timer};
use crate::{sched, syscall};
use abi::{
    CHANNEL_RIGHTS, CLIENT_GONE, Call, Error, Handle, INFO_KERNEL_STATS, INFO_PROCESS_HANDLES,
    INFO_PROCESS_MEMORY, INFO_PROCESS_STATE, INIT_BOOT_IMAGE, INIT_PROCESS, INIT_RESOURCE,
    INIT_RESOURCE_RIGHTS, INIT_THREAD, KernelStats, MAX_SLOTS, NO_WAIT, Notification, OWNER_RIGHTS,
    ProcessHandles, ProcessMemory, ProcessState, Rights, START_CHANNEL, Source,
};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::handles::CHUNK;
use kcore::layout::{LINEAR_BASE, USER_END};
use kcore::paging::{Attrs, page_descriptor};
use kcore::sched::State;

/// The line `debug_write_checks_its_arguments` prints: 64 bytes, all of
/// x2-x9. xtask looks for it in the output.
const LINE: &[u8; 64] = b"kernel test: debug_write prints all 64 bytes of x2-x9 in order.\n";
/// A line the same test prints with `#` past its length in x2-x9, then a
/// newline; xtask wants it whole.
const STOPS: &[u8] = b"debug_write stops at its length";

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
        let process = process::create_root(QUOTA, LIMIT, ceiling).map_err(|_| "no process")?;
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
fn with_caller(body: impl FnOnce(&Caller) -> Result<(), &'static str>) -> Result<(), &'static str> {
    let caller = Caller::new()?;
    let result = body(&caller);
    caller.release();
    result
}

/// Numbers no call has fail and change x0 alone. Numbers kept for calls
/// of later milestones behave the same, but tests leave them alone: they
/// stop failing when their calls come.
pub fn unknown_system_calls_fail_with_invalid_args(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let args: [u64; 10] = core::array::from_fn(|i| i as u64 + 1);
        for number in [0, 29, 0xFEFF] {
            c.fails(number, &args, Error::InvalidArgs)?;
        }
        Ok(())
    })
}

/// Values come before handles, a bad handle before a wrong type, a wrong
/// type before a missing right (spec 11); a good call prints its bytes and
/// returns their count in x1.
pub fn debug_write_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let debug = c.insert(Object::Resource, Rights::DEBUG)?;
        let plain = c.insert(Object::Resource, Rights::DEVICE | Rights::KSTATS)?;
        let own = c.insert(Object::Process(c.process), OWNER_RIGHTS)?;
        let closed = c.insert(Object::Resource, Rights::DEBUG)?;
        c.close(closed)?;
        let result = debug_write_cases(c, [debug, plain, own, closed]);
        // The handle to its own process would keep the process alive.
        c.close(own)?;
        result
    })
}

fn debug_write_cases(c: &Caller, handles: [Handle; 4]) -> Result<(), &'static str> {
    let [debug, plain, own, closed] = handles.map(|h| h.0);
    let n = Call::DebugWrite.number();
    c.fails(n, &[debug, 65], Error::InvalidArgs)?;
    c.fails(n, &[debug, u64::MAX], Error::InvalidArgs)?;
    c.fails(n, &[debug, 1 << 32], Error::InvalidArgs)?;
    c.fails(n, &[closed, 65], Error::InvalidArgs)?;
    c.fails(n, &[closed, 1], Error::BadHandle)?;
    c.fails(n, &[0, 1], Error::BadHandle)?;
    c.fails(n, &[own, 1], Error::WrongType)?;
    c.fails(n, &[plain, 1], Error::AccessDenied)?;
    c.succeeds(n, &[debug, 0], &[0])?;
    let mut args = [0; 10];
    args[0] = debug;
    args[1] = LINE.len() as u64;
    args[2..].copy_from_slice(&abi::inline_words(LINE));
    c.succeeds(n, &args, &[64])?;
    // Only the bytes of the length go out.
    let mut bytes = [b'#'; abi::INLINE_MAX];
    bytes[..STOPS.len()].copy_from_slice(STOPS);
    args[1] = STOPS.len() as u64;
    args[2..].copy_from_slice(&abi::inline_words(&bytes));
    c.succeeds(n, &args, &[STOPS.len() as u64])?;
    args[1] = 1;
    args[2..].copy_from_slice(&abi::inline_words(b"\n"));
    c.succeeds(n, &args, &[1])
}

/// PROCESS_STATE of a live process: four zeros in x1-x4, whatever rights
/// the handle carries. Unknown kinds, a nonzero x2 and handles to other
/// objects fail.
pub fn object_info_reports_a_live_process(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), Rights::NONE)?;
        let resource = c.insert(Object::Resource, Rights::DEBUG)?;
        let thread = c.insert(Object::Thread(c.thread), OWNER_RIGHTS)?;
        let result = object_info_cases(c, [own, resource, thread]);
        c.close(own)?;
        c.close(thread)?;
        result
    })
}

fn object_info_cases(c: &Caller, handles: [Handle; 3]) -> Result<(), &'static str> {
    let [own, resource, thread] = handles.map(|h| h.0);
    let n = Call::ObjectInfo.number();
    let state = INFO_PROCESS_STATE;
    c.fails(n, &[own, 0, 0], Error::InvalidArgs)?;
    c.fails(n, &[own, INFO_KERNEL_STATS + 1, 0], Error::InvalidArgs)?;
    c.fails(n, &[own, state | 1 << 32, 0], Error::InvalidArgs)?;
    c.fails(n, &[own, state, 8], Error::InvalidArgs)?;
    c.fails(n, &[0, 0, 0], Error::InvalidArgs)?;
    c.fails(n, &[0, state, 0], Error::BadHandle)?;
    c.fails(n, &[resource, state, 0], Error::WrongType)?;
    c.fails(n, &[thread, state, 0], Error::WrongType)?;
    c.succeeds(n, &[own, state, 0], &ProcessState::Alive.to_words())
}

/// PROCESS_MEMORY and PROCESS_HANDLES take a process handle with any
/// rights and return its quota and its table in x1-x3; KERNEL_STATS takes
/// the system resource with KSTATS and returns what the kernel counts in
/// x1-x7 (spec 11, 16). The kind and x2 come before the handle, a wrong
/// type before a missing right, and x8 and x9 keep their marks.
pub fn object_info_reports_memory_handles_and_statistics(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        let own = c.insert(Object::Process(c.process), Rights::NONE)?;
        let stats = c.insert(Object::Resource, Rights::KSTATS)?;
        let debug = c.insert(Object::Resource, Rights::DEBUG)?;
        let result = info_kinds_cases(c, [own, stats, debug]);
        c.close(own)?;
        result
    })
}

fn info_kinds_cases(c: &Caller, handles: [Handle; 3]) -> Result<(), &'static str> {
    let [own, stats, debug] = handles.map(|h| h.0);
    let n = Call::ObjectInfo.number();
    let (memory, table, kernel) = (INFO_PROCESS_MEMORY, INFO_PROCESS_HANDLES, INFO_KERNEL_STATS);
    for kind in [memory, table, kernel] {
        c.fails(n, &[own, kind, 1], Error::InvalidArgs)?;
        c.fails(n, &[0, kind, 1], Error::InvalidArgs)?;
        c.fails(n, &[0, kind, 0], Error::BadHandle)?;
    }
    c.fails(n, &[stats, memory, 0], Error::WrongType)?;
    c.fails(n, &[stats, table, 0], Error::WrongType)?;
    c.fails(n, &[own, kernel, 0], Error::WrongType)?;
    c.fails(n, &[debug, kernel, 0], Error::AccessDenied)?;
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
        live: 3,
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
        longest_batch: crate::timer::longest_batch(),
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

/// Init's first handles get the values abi fixes: the system resource,
/// init's process and thread, and a freed entry for the boot image whose
/// value stays bad.
pub fn init_handles_have_their_fixed_values(_: &Boot) -> Result<(), &'static str> {
    with_caller(|c| {
        process::install_init_handles(c.process, c.thread).map_err(|_| "no init handles")?;
        let result = init_handle_cases(c);
        c.close(INIT_PROCESS)?;
        c.close(INIT_THREAD)?;
        c.close(INIT_RESOURCE)?;
        result
    })
}

fn init_handle_cases(c: &Caller) -> Result<(), &'static str> {
    // SAFETY: the process is the test's, and nothing changes it meanwhile.
    let p = unsafe { c.process.as_ref() };
    check(
        p.lookup(INIT_RESOURCE, INIT_RESOURCE_RIGHTS, Object::resource)
            .is_ok(),
        "INIT_RESOURCE is not the system resource with all its rights",
    )?;
    check(
        p.lookup(INIT_PROCESS, OWNER_RIGHTS, Object::process) == Ok(c.process),
        "INIT_PROCESS is not init's process",
    )?;
    check(
        p.lookup(INIT_THREAD, OWNER_RIGHTS, Object::thread) == Ok(c.thread),
        "INIT_THREAD is not init's first thread",
    )?;
    let n = Call::HandleClose.number();
    c.fails(n, &[INIT_BOOT_IMAGE.0], Error::BadHandle)?;
    c.fails(
        Call::ObjectInfo.number(),
        &[INIT_BOOT_IMAGE.0, INFO_PROCESS_STATE, 0],
        Error::BadHandle,
    )?;
    // The freed entry comes back with its next generation.
    let next = c.insert(Object::Resource, Rights::NONE)?;
    let fresh = next == Handle::new(INIT_BOOT_IMAGE.index(), 2);
    c.close(next)?;
    check(fresh, "the boot image's entry came back at another value")
}

/// thread_set_priority checks the values first, then the handle, then the
/// two ceilings, the target thread's process's and the caller's, then the
/// thread's state (spec 11). A stopped thread only takes the new values.
/// The caller's process has ceiling 30; the target threads' processes 20
/// and 63.
pub fn thread_set_priority_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    let callers = [30, 20, 63].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(c), Ok(low), Ok(high)] => set_priority_handles(c, low, high),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result
}

fn set_priority_handles(c: &Caller, low: &Caller, high: &Caller) -> Result<(), &'static str> {
    let handles = [
        c.insert(Object::Thread(low.thread), Rights::MANAGE)?,
        c.insert(Object::Thread(high.thread), Rights::MANAGE)?,
        c.insert(Object::Thread(low.thread), Rights::DUPLICATE)?,
        c.insert(Object::Resource, Rights::DEBUG)?,
        c.insert(Object::Resource, Rights::DEBUG)?,
    ];
    c.close(handles[4])?;
    set_priority_cases(c, low.thread, handles)
}

fn set_priority_cases(
    c: &Caller,
    low: NonNull<Thread>,
    handles: [Handle; 5],
) -> Result<(), &'static str> {
    let [to_low, to_high, no_manage, resource, closed] = handles.map(|h| h.0);
    let n = Call::ThreadSetPriority.number();
    let (rr, fifo) = (Policy::RoundRobin as u64, Policy::Fifo as u64);
    for (priority, policy) in [(0, rr), (64, rr), (0x100 | 10, rr), (10, 2), (10, 1 << 32)] {
        c.fails(n, &[to_low, priority, policy], Error::InvalidArgs)?;
    }
    c.fails(n, &[closed, 64, rr], Error::InvalidArgs)?;
    c.fails(n, &[closed, 10, rr], Error::BadHandle)?;
    c.fails(n, &[resource, 10, rr], Error::WrongType)?;
    c.fails(n, &[no_manage, 10, rr], Error::AccessDenied)?;
    // Above the ceiling of the target's process, 20, under the caller's.
    c.fails(n, &[to_low, 21, rr], Error::AccessDenied)?;
    // Under the ceiling of the target's process, 63, above the caller's.
    c.fails(n, &[to_high, 31, rr], Error::AccessDenied)?;
    c.succeeds(n, &[to_high, 30, rr], &[])?;
    c.succeeds(n, &[to_low, 20, rr], &[])?;
    // SAFETY: the thread is the test's and never runs.
    let t = unsafe { low.as_ref() };
    check(
        t.sched.base() == 20
            && t.sched.priority() == 20
            && t.sched.policy() == Policy::RoundRobin
            && t.sched.state() == State::Stopped,
        "a stopped thread did not take its new priority and policy",
    )?;
    // A thread that ended: BAD_STATE, which comes after the ceilings.
    sched::start(low).map_err(|_| "the thread did not start")?;
    // SAFETY: the test holds its own reference to the thread.
    unsafe { sched::exit(low, CAUSE) };
    c.fails(n, &[to_low, 21, fifo], Error::AccessDenied)?;
    c.fails(n, &[to_low, 20, fifo], Error::BadState)
}

/// process_create checks the values first, then the exit channel and the
/// start channel, then the ceiling against the caller's, then the quotas
/// (spec 11); a good call returns a handle with the owner's rights to a
/// live process with the ceiling given, a child of the caller's process
/// (spec 4). With the caller's table full it fails with LIMIT_REACHED, and
/// the new process goes again. The caller's ceiling is 30. Channels in x3
/// and x5 have cases of their own (`exit_and_start_cases`).
pub fn process_create_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    let processes = process::in_use();
    let c = Caller::with_ceiling(30)?;
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
    let page = PAGE_SIZE;
    let resource = c.insert(Object::Resource, Rights::DEBUG)?.0;
    let closed = c.insert(Object::Resource, Rights::DEBUG)?;
    c.close(closed)?;
    let closed = closed.0;
    for [quota, limit, ceiling] in [
        [0, 16, 20],
        [page - 1, 16, 20],
        [page + 8, 16, 20],
        [page, 0, 20],
        [page, 16_385, 20],
        [page, 1 << 32 | 16, 20],
        [page, 16, 0],
        [page, 16, 64],
        [page, 16, 0x100 | 20],
    ] {
        c.fails(n, &[quota, limit, ceiling, 0, 0, 0], Error::InvalidArgs)?;
        // Values come before handles.
        c.fails(
            n,
            &[quota, limit, ceiling, closed, 5, closed],
            Error::InvalidArgs,
        )?;
    }
    // A notification priority without a channel, a channel without one.
    c.fails(n, &[page, 16, 20, 0, 5, 0], Error::InvalidArgs)?;
    c.fails(n, &[page, 16, 20, closed, 0, 0], Error::InvalidArgs)?;
    c.fails(n, &[page, 16, 20, closed, 5, 0], Error::BadHandle)?;
    // The system resource is no channel.
    c.fails(n, &[page, 16, 20, resource, 5, 0], Error::WrongType)?;
    c.fails(n, &[page, 16, 20, 0, 0, closed], Error::BadHandle)?;
    c.fails(n, &[page, 16, 20, 0, 0, resource], Error::WrongType)?;
    // The exit channel comes before the start channel.
    c.fails(n, &[page, 16, 20, resource, 5, closed], Error::WrongType)?;
    // Handles come before the ceiling.
    c.fails(n, &[page, 16, 31, closed, 5, 0], Error::BadHandle)?;
    c.fails(n, &[page, 16, 31, 0, 0, closed], Error::BadHandle)?;
    c.fails(n, &[page, 16, 31, 0, 0, 0], Error::AccessDenied)?;
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
/// there is NO_MEMORY, after the ceiling. The least quota covers the
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
    c.fails(n, &[over, 16, 31, 0, 0, 0], Error::AccessDenied)?;
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

/// Channels in x3 and x5 of process_create, where a caller below the
/// highest ceiling matters; the test init checks the rest from EL0
/// (spec 11, 13.3). x4 above the caller's ceiling fails with ACCESS_DENIED
/// after the handles, and x3 on a channel that closed with PEER_CLOSED
/// only after the ceilings; the caller's full table comes before the
/// channel's slots and the quota (LIMIT_REACHED). A good call moves x5
/// into entry 0 of the child's table with its rights, and the caller's
/// handle goes.
fn exit_and_start_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::ProcessCreate.number();
    let q = CHILD_QUOTA;
    let closed = c.insert(Object::Resource, Rights::NONE)?;
    c.close(closed)?;
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let shut = c.created(Call::CreateChannel.number(), &[10])?;
    let result = channel_of(c, shut)
        .and_then(|s| c.insert(Object::Channel(s), Rights::NOTIFY))
        .and_then(|left| {
            c.close(shut)?;
            let (h, left) = (h.0, left.0);
            c.fails(n, &[q, 16, 20, closed.0, 31, h], Error::BadHandle)?;
            c.fails(n, &[q, 16, 20, h, 31, closed.0], Error::BadHandle)?;
            c.fails(n, &[q, 16, 20, h, 31, 0], Error::AccessDenied)?;
            c.fails(n, &[q, 16, 20, left, 31, 0], Error::AccessDenied)?;
            c.fails(n, &[q, 16, 20, left, 30, 0], Error::PeerClosed)?;
            c.close(Handle(left))?;
            with_full_table(c, n, &[q, 16, 20, h, 5, 0])
        })
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

/// thread_create checks the values first (entry, stack, priority, policy,
/// buffer), then the handle to the process, then the ceilings of that
/// process and of the caller, then whether the buffer's page is free there
/// (spec 11). A good call makes a stopped thread whose buffer is a zeroed
/// page, readable and writable, never executable, and returns a handle
/// with the owner's rights; the page goes with the thread. With the
/// caller's table full it fails with LIMIT_REACHED, and the new thread and
/// its page go again. The caller's ceiling is 30; the target processes
/// have 20 and 63.
pub fn thread_create_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    let callers = [30, 20, 63].map(Caller::with_ceiling);
    let result = match &callers {
        [Ok(c), Ok(low), Ok(high)] => thread_create_handles(c, low, high),
        _ => Err("no process or thread"),
    };
    for caller in callers.into_iter().flatten() {
        caller.release();
    }
    result
}

fn thread_create_handles(c: &Caller, low: &Caller, high: &Caller) -> Result<(), &'static str> {
    let handles = [
        c.insert(Object::Process(low.process), Rights::MANAGE)?,
        c.insert(Object::Process(high.process), Rights::MANAGE)?,
        c.insert(Object::Process(low.process), Rights::DUPLICATE)?,
        c.insert(Object::Thread(low.thread), Rights::MANAGE)?,
        c.insert(Object::Resource, Rights::DEBUG)?,
    ];
    c.close(handles[4])?;
    thread_create_cases(c, low.process, handles)
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
    handles: [Handle; 5],
) -> Result<(), &'static str> {
    let [to_low, to_high, no_manage, thread, closed] = handles.map(|h| h.0);
    let n = Call::ThreadCreate.number();
    let (entry, stack, top) = (USER_VA as u64, 0x80_1000, USER_END as u64);
    // Each bad value with a good handle and with a closed one: values
    // come before handles.
    for h in [to_low, closed] {
        for args in [
            thread_args(h, top, stack, 10, FIFO, BUFFER),
            thread_args(h, entry + 2, stack, 10, FIFO, BUFFER),
            thread_args(h, entry, stack - 8, 10, FIFO, BUFFER),
            thread_args(h, entry, top + 16, 10, FIFO, BUFFER),
            thread_args(h, entry, stack, 0, FIFO, BUFFER),
            thread_args(h, entry, stack, 64, FIFO, BUFFER),
            thread_args(h, entry, stack, 10, 2, BUFFER),
            thread_args(h, entry, stack, 10, FIFO, BUFFER + 8),
            thread_args(h, entry, stack, 10, FIFO, top),
            thread_args(h, entry, stack, 10, FIFO, 0),
        ] {
            c.fails(n, &args, Error::InvalidArgs)?;
        }
    }
    let good = |h, priority| thread_args(h, entry, stack, priority, FIFO, BUFFER);
    c.fails(n, &good(closed, 10), Error::BadHandle)?;
    c.fails(n, &good(thread, 10), Error::WrongType)?;
    c.fails(n, &good(no_manage, 10), Error::AccessDenied)?;
    // Above the target's ceiling, 20, under the caller's; then above the
    // caller's, 30, under the target's.
    c.fails(n, &good(to_low, 21), Error::AccessDenied)?;
    c.fails(n, &good(to_high, 31), Error::AccessDenied)?;
    let h = c.created(n, &good(to_low, 20))?;
    let result = new_thread_cases(c, low, h);
    // The page is taken: INVALID_ARGS, which comes after the ceilings.
    c.fails(n, &good(to_low, 20), Error::InvalidArgs)?;
    c.fails(n, &good(to_low, 21), Error::AccessDenied)?;
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

/// process_kill ends a process whatever state its threads are in: a ready
/// thread leaves the queue, a stopped one ends where it is (spec 11), both
/// in the call. The process's space and its threads' buffers go with the
/// cleanup at the caller's level, which runs before the caller does again:
/// here the test runs the queue itself. Handles keep the shells, and
/// object_info reports «killed». Killing it again succeeds; thread_start,
/// thread_create and thread_set_priority find it and its threads ended
/// (BAD_STATE). thread_start and process_kill check their handles first.
/// A running thread's case is `process_kills_itself` at EL0.
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
    let (Ok(cp), Ok(tr), Ok(ts)) = (
        p.lookup(child, OWNER_RIGHTS, Object::process),
        p.lookup(ready, OWNER_RIGHTS, Object::thread),
        p.lookup(stopped, OWNER_RIGHTS, Object::thread),
    ) else {
        return Err("the new handles do not name their objects");
    };
    let weak = [
        c.insert(Object::Process(cp), Rights::DUPLICATE)?,
        c.insert(Object::Thread(tr), Rights::DUPLICATE)?,
    ];
    let result = kill_calls(c, handles, weak, [tr, ts]);
    for h in weak {
        c.close(h)?;
    }
    result
}

fn kill_calls(
    c: &Caller,
    [child, ready, stopped]: [Handle; 3],
    [weak_child, weak_thread]: [Handle; 2],
    [tr, ts]: [NonNull<Thread>; 2],
) -> Result<(), &'static str> {
    let start = Call::ThreadStart.number();
    c.fails(start, &[0], Error::BadHandle)?;
    c.fails(start, &[child.0], Error::WrongType)?;
    c.fails(start, &[weak_thread.0], Error::AccessDenied)?;
    c.succeeds(start, &[ready.0], &[])?;
    c.fails(start, &[ready.0], Error::BadState)?;
    check(
        sched::first(10) == Some(tr),
        "a started thread is not ready",
    )?;
    let kill = Call::ProcessKill.number();
    c.fails(kill, &[0], Error::BadHandle)?;
    c.fails(kill, &[ready.0], Error::WrongType)?;
    c.fails(kill, &[weak_child.0], Error::AccessDenied)?;
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
    )?;
    let info = Call::ObjectInfo.number();
    let killed = ProcessState::Killed.to_words();
    c.succeeds(info, &[child.0, INFO_PROCESS_STATE, 0], &killed)?;
    c.succeeds(kill, &[child.0], &[])?;
    c.fails(start, &[stopped.0], Error::BadState)?;
    c.fails(Call::ThreadCreate.number(), &args, Error::BadState)?;
    let set = Call::ThreadSetPriority.number();
    c.fails(set, &[ready.0, 10, FIFO], Error::BadState)
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
    let q = process::quota(c.process);
    let rest = q.limit() - q.returned() - q.used();
    process::charge(c.process, rest).map_err(|_| "the rest of the quota did not charge")?;
    let result = body();
    process::refund(c.process, rest);
    result
}

/// channel_create, notify and receive check in the order of spec 11 and
/// change x0 alone on an error: values first (a priority outside 1-63, bit
/// 63 of the bits, flags other than NO_WAIT), then the handle (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without NOTIFY or RECEIVE), then the ceiling
/// (a priority above the caller's 30), then the caller's table
/// (LIMIT_REACHED) and its quota for a page of its pool of channels
/// (NO_MEMORY), with nothing made. A good channel_create returns a handle
/// with abi::CHANNEL_RIGHTS to a channel the caller pays for; notify
/// returns nothing; receive with NO_WAIT on an empty channel fails with
/// WOULD_BLOCK, and otherwise returns the notification in x1-x11.
pub fn channel_calls_check_their_arguments(_: &Boot) -> Result<(), &'static str> {
    let channels = channel::in_use();
    let c = Caller::with_ceiling(30)?;
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
    for priority in [0, 64, 0x100 | 10] {
        c.fails(n, &[priority], Error::InvalidArgs)?;
    }
    c.fails(n, &[31], Error::AccessDenied)?;
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
        )?;
        let notify_only = c.insert(Object::Channel(ch), Rights::NOTIFY)?;
        let receive_only = c.insert(Object::Channel(ch), Rights::RECEIVE)?;
        let result = notify_receive_cases(c, [h, notify_only, receive_only, resource]);
        c.close(notify_only)?;
        c.close(receive_only)?;
        result
    });
    c.close(h)?;
    c.close(resource)?;
    result
}

fn notify_receive_cases(c: &Caller, handles: [Handle; 4]) -> Result<(), &'static str> {
    let [h, notify_only, receive_only, resource] = handles.map(|h| h.0);
    let closed = c.insert(Object::Resource, Rights::NONE)?;
    c.close(closed)?;
    let closed = closed.0;
    let (notify, receive) = (Call::Notify.number(), Call::Receive.number());
    c.fails(notify, &[closed, 1 << 63], Error::InvalidArgs)?;
    c.fails(notify, &[closed, 1], Error::BadHandle)?;
    c.fails(notify, &[resource, 1], Error::WrongType)?;
    c.fails(notify, &[receive_only, 1], Error::AccessDenied)?;
    for flags in [1, NO_WAIT | 1 << 17, 1 << 63] {
        c.fails(receive, &[closed, flags], Error::InvalidArgs)?;
    }
    c.fails(receive, &[closed, NO_WAIT], Error::BadHandle)?;
    c.fails(receive, &[resource, NO_WAIT], Error::WrongType)?;
    c.fails(receive, &[notify_only, NO_WAIT], Error::AccessDenied)?;
    c.fails(receive, &[receive_only, NO_WAIT], Error::WouldBlock)?;
    c.succeeds(notify, &[notify_only, 0b110], &[])?;
    c.succeeds(notify, &[h, 1], &[])?;
    let mut t = c.thread;
    // SAFETY: the thread is the test's and never runs.
    unsafe { t.as_mut() }.regs.x[10..12].copy_from_slice(&[0x5A, 0x5B]);
    // A slot is queued: receive takes it and does not wait.
    c.succeeds(receive, &[receive_only, 0], &unlabeled(0b111, 2))?;
    // SAFETY: as above.
    let (label, token) = unsafe { (t.as_ref().regs.x[10], t.as_ref().regs.x[11]) };
    check(
        (label, token) == (0, 0),
        "receive did not write the label and the token in x10 and x11",
    )?;
    c.fails(receive, &[h, NO_WAIT], Error::WouldBlock)
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

/// Spec 15.2 (refusals): when the last handle with RECEIVE goes, the
/// channel closes (spec 6.5, 6.8), and the slot queued in it goes at the
/// stage Close. notify through a handle that is left, which a program gets
/// with handle_duplicate (spec 5.2, 5.3) and the kernel puts in here, fails
/// with PEER_CLOSED after its own checks, and changes x0 alone. Its last
/// handle lets the channel go.
pub fn notify_after_close_is_peer_closed(_: &Boot) -> Result<(), &'static str> {
    let channels = channel::in_use();
    with_caller(|c| {
        let n = Call::Notify.number();
        let h = c.created(Call::CreateChannel.number(), &[10])?;
        let left = channel_of(c, h).and_then(|ch| c.insert(Object::Channel(ch), Rights::NOTIFY));
        c.succeeds(n, &[h.0, 1], &[])?;
        c.close(h)?;
        let left = left?;
        let queued = cleanup::len();
        cleanup::drain();
        let result = c
            .fails(n, &[left.0, 1 << 63], Error::InvalidArgs)
            .and_then(|()| c.fails(n, &[left.0, 1], Error::PeerClosed));
        c.close(left)?;
        result?;
        check(
            queued == 1,
            "the closed channel did not go to its stage Close with its slot queued",
        )
    })?;
    check(
        channel::in_use() == channels,
        "the channel stayed after its last handle",
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

/// handle_duplicate(x0 handle, x1 rights, x2 label, x3 priority) checks in
/// the order of spec 11 and changes x0 alone on an error: values first
/// (bits no right has, a priority without a label, a label without one, a
/// priority outside 1-63), then the handle (BAD_HANDLE; a label on a
/// handle that is no channel, WRONG_TYPE; no DUPLICATE or a right the
/// original lacks, ACCESS_DENIED), then the ceiling (a priority above the
/// caller's 30), then the state (a new label on a handle with one,
/// BAD_STATE; on a closed channel, PEER_CLOSED), then the resources in the
/// order the call takes them: the caller's table (LIMIT_REACHED), the
/// channel's slots (LIMIT_REACHED, abi::MAX_SLOTS with the slot of label
/// 0), the caller's quota for a page of its pool of sessions (NO_MEMORY);
/// nothing is made then. A good call returns the copy in x1 alone: with
/// label 0 it names the same object, a session's copy the same session;
/// a label makes a session of the channel at the priority, which the
/// caller pays for. A copy with a label and RECEIVE keeps the channel
/// open.
pub fn handle_duplicate_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    let (sessions, channels) = (session::in_use(), channel::in_use());
    let callers = [30, 63].map(Caller::with_ceiling);
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
    let result = channel_of(c, h).and_then(|ch| {
        let resource = c.insert(Object::Resource, Rights::DEBUG | Rights::DUPLICATE)?;
        let notify_only = c.insert(Object::Channel(ch), Rights::NOTIFY)?;
        let own = c.insert(Object::Process(c.process), Rights::NONE)?;
        let result = duplicate_check_order(c, [h, resource, notify_only, own])
            .and_then(|()| duplicate_resources(c, h))
            .and_then(|()| duplicate_results(c, [h, resource]))
            .and_then(|()| slots_come_before_the_quota(c, other));
        for handle in [resource, notify_only, own] {
            c.close(handle)?;
        }
        result
    });
    // Closed already when the cases went through.
    let _ = process::close_handle(c.process, h, super::CAUSE);
    result
}

fn duplicate_check_order(c: &Caller, handles: [Handle; 4]) -> Result<(), &'static str> {
    let n = Call::HandleDuplicate.number();
    let [h, resource, notify_only, own] = handles.map(|h| h.0);
    let closed = c.insert(Object::Resource, Rights::NONE)?;
    c.close(closed)?;
    let closed = closed.0;
    let notify = u64::from(Rights::NOTIFY.0);
    for [rights, label, priority] in [
        [1 << 12, 0, 0],
        [1 << 32, 0, 0],
        [0, 0, 5],
        [0, 7, 0],
        [0, 7, 64],
        [0, 7, 0x100 | 5],
    ] {
        c.fails(n, &[closed, rights, label, priority], Error::InvalidArgs)?;
    }
    c.fails(n, &[closed, 0, 0, 0], Error::BadHandle)?;
    c.fails(n, &[0, 0, 7, 5], Error::BadHandle)?;
    // A label on what is no channel, before the missing right.
    c.fails(n, &[resource, 0, 7, 5], Error::WrongType)?;
    c.fails(n, &[own, 0, 7, 5], Error::WrongType)?;
    c.fails(n, &[own, 0, 0, 0], Error::AccessDenied)?;
    c.fails(n, &[notify_only, notify, 0, 0], Error::AccessDenied)?;
    c.fails(n, &[notify_only, notify, 7, 5], Error::AccessDenied)?;
    let more = u64::from((Rights::DEBUG | Rights::KSTATS).0);
    c.fails(n, &[resource, more, 0, 0], Error::AccessDenied)?;
    c.fails(
        n,
        &[h, u64::from(Rights::MANAGE.0), 0, 0],
        Error::AccessDenied,
    )?;
    // The ceiling comes after the handle.
    c.fails(n, &[closed, notify, 7, 31], Error::BadHandle)?;
    c.fails(n, &[h, notify, 7, 31], Error::AccessDenied)
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
/// session of the channel, a new label on a session (BAD_STATE, after the
/// ceiling), and a copy with a label and RECEIVE that keeps the channel
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
    c.fails(n, &[first.0, notify, 8, 31], Error::AccessDenied)?;
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

/// timer_create, timer_set, timer_cancel and clock_now check in the order
/// of spec 11 and change x0 alone on an error: the priority first (outside
/// 1-63), then the handle (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// RECEIVE or MANAGE), then the ceiling (a priority above the caller's
/// 30), then the caller's table (LIMIT_REACHED) and its quota for a page
/// of its pool of timers (NO_MEMORY), with nothing made. A good
/// timer_create returns a handle with abi::OWNER_RIGHTS to a timer the
/// caller pays for, not armed; timer_set and timer_cancel return nothing,
/// and cancelling a timer that is not armed is no error. timer_set on a
/// closed channel fails with PEER_CLOSED and leaves the timer armed as it
/// was. clock_now returns the counter in nanoseconds in x1 alone.
pub fn timer_calls_check_their_arguments(_: &Boot) -> Result<(), &'static str> {
    let timers = timers::in_use();
    let c = Caller::with_ceiling(30)?;
    let result = timer_create_cases(&c).and_then(|()| clock_now_case(&c));
    c.release();
    result?;
    check(
        timers::in_use() == timers,
        "a timer of the test stayed in its pool",
    )
}

fn timer_create_cases(c: &Caller) -> Result<(), &'static str> {
    let n = Call::TimerCreate.number();
    let resource = c.insert(Object::Resource, Rights::NONE)?;
    let closed = c.insert(Object::Resource, Rights::NONE)?;
    c.close(closed)?;
    let h = c.created(Call::CreateChannel.number(), &[10])?;
    let result = channel_of(c, h).and_then(|ch| {
        let notify_only = c.insert(Object::Channel(ch), Rights::NOTIFY)?;
        for priority in [0, 64, 0x100 | 10] {
            c.fails(n, &[closed.0, priority], Error::InvalidArgs)?;
        }
        c.fails(n, &[closed.0, 10], Error::BadHandle)?;
        c.fails(n, &[resource.0, 10], Error::WrongType)?;
        c.fails(n, &[notify_only.0, 10], Error::AccessDenied)?;
        c.fails(n, &[h.0, 31], Error::AccessDenied)?;
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
        let result = timer_set_cases(c, [h, t, notify_only, resource, closed]);
        c.close(t)?;
        c.close(notify_only)?;
        result
    });
    // The case of the closed channel closed it already.
    let _ = process::close_handle(c.process, h, CAUSE);
    c.close(resource)?;
    result
}

fn timer_set_cases(c: &Caller, handles: [Handle; 5]) -> Result<(), &'static str> {
    let [h, t, notify_only, resource, closed] = handles;
    let (set, cancel) = (Call::TimerSet.number(), Call::TimerCancel.number());
    let tm = timer_of(c, t)?;
    // SAFETY: the caller's process is the test's.
    let rights = unsafe { c.process.as_ref() }.lookup(t, OWNER_RIGHTS, Object::timer);
    check(
        rights.is_ok() && timers::payer(tm) == c.process && timers::deadline(tm).is_none(),
        "the handle does not carry the owner's rights, the caller does not pay, or the timer is armed",
    )?;
    let seen = c.insert(Object::Timer(tm), Rights::DUPLICATE)?;
    for (n, args) in [(set, &[closed.0, 0][..]), (cancel, &[closed.0][..])] {
        c.fails(n, args, Error::BadHandle)?;
    }
    c.fails(set, &[resource.0, 0], Error::WrongType)?;
    c.fails(cancel, &[h.0], Error::WrongType)?;
    c.fails(set, &[seen.0, 0], Error::AccessDenied)?;
    c.fails(cancel, &[seen.0], Error::AccessDenied)?;
    c.close(seen)?;
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
    c.fails(
        Call::Notify.number(),
        &[notify_only.0, 1],
        Error::PeerClosed,
    )?;
    check(
        timers::deadline(tm) == Some(at) && !timers::posted(tm),
        "timer_set on a closed channel changed the timer",
    )?;
    c.succeeds(cancel, &[t.0], &[])
}

fn clock_now_case(c: &Caller) -> Result<(), &'static str> {
    let clock = timer::clock();
    let before = clock.ticks_to_ns(timer::now());
    let got = c.call(Call::ClockNow.number(), &[]);
    let after = clock.ticks_to_ns(timer::now());
    let mut want = with_marks(&[]);
    want[0] = 0;
    want[1] = got[1];
    check(
        got == want && (before..=after).contains(&got[1]),
        "clock_now did not return the counter in nanoseconds in x1 alone",
    )
}

/// timer_set rounds its deadline up to counter ticks (spec 10): for every
/// deadline of a stretch of 64 ns a second away, on the ticks and between
/// them, the timer stands in the heap at the first tick whose time, as
/// clock_now counts it, is not before the deadline; the tick before it is.
pub fn timer_never_fires_early(_: &Boot) -> Result<(), &'static str> {
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
/// back into the past; each time receive takes one expiry, bit 0 once.
pub fn timer_in_the_past_fires_at_once(_: &Boot) -> Result<(), &'static str> {
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
/// holds it, and the heap still does until its portion. The kernel's timer
/// interrupt at its deadline takes it off the heap and posts nothing; its
/// portion then lets it go.
pub fn dying_timer_does_not_fire(_: &Boot) -> Result<(), &'static str> {
    let timers = timers::in_use();
    with_caller(|c| {
        with_timer(c, |h, t, tm| {
            c.succeeds(Call::TimerSet.number(), &[t.0, a_second_away()], &[])?;
            let at = timers::deadline(tm).ok_or("the timer is not armed")?;
            c.close(t)?;
            let queued = cleanup::len();
            timers::expire(at);
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
