// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests of the system calls (spec 11, 12). The kernel makes each
//! call for a thread that never runs, as if the thread had made it, and
//! checks every register the call may write: on an error only x0 changes,
//! on success x0 is 0 and the values follow in x1 and up. The same calls
//! from EL0 are in `el0`.

use super::check;
use crate::boot::Boot;
use crate::mm::phys;
use crate::object::Object;
use crate::process::{self, Process};
use crate::thread::{self, Policy, Thread};
use crate::{sched, syscall};
use abi::{
    Call, Error, Handle, INFO_PROCESS_STATE, INIT_BOOT_IMAGE, INIT_PROCESS, INIT_RESOURCE,
    INIT_RESOURCE_RIGHTS, INIT_THREAD, OWNER_RIGHTS, ProcessState, Rights,
};
use core::ptr::NonNull;
use kcore::frames::PAGE_SIZE;
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
        let process = process::create(LIMIT, ceiling).map_err(|_| "no process")?;
        match thread::create(process, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
            Ok(thread) => Ok(Caller { process, thread }),
            Err(_) => {
                // SAFETY: the process is the test's, and nothing uses it afterwards.
                unsafe { process::release(process) };
                Err("no thread")
            }
        }
    }

    /// Drops the test's references; the thread and the process go unless
    /// a handle still holds them.
    fn release(self) {
        // SAFETY: the references are the test's, and nothing uses them afterwards.
        unsafe {
            thread::release(self.thread);
            process::release(self.process);
        }
    }

    fn insert(&self, object: Object, rights: Rights) -> Result<Handle, &'static str> {
        process::insert_handle(self.process, object, rights).map_err(|_| "a handle did not go in")
    }

    fn close(&self, h: Handle) -> Result<(), &'static str> {
        process::close_handle(self.process, h).map_err(|_| "a handle did not close")
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
/// the handle carries. Other kinds, a nonzero x2 and handles to other
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
    c.fails(n, &[own, 2, 0], Error::InvalidArgs)?;
    c.fails(n, &[own, state | 1 << 32, 0], Error::InvalidArgs)?;
    c.fails(n, &[own, state, 8], Error::InvalidArgs)?;
    c.fails(n, &[0, 0, 0], Error::InvalidArgs)?;
    c.fails(n, &[0, state, 0], Error::BadHandle)?;
    c.fails(n, &[resource, state, 0], Error::WrongType)?;
    c.fails(n, &[thread, state, 0], Error::WrongType)?;
    c.succeeds(n, &[own, state, 0], &ProcessState::Alive.to_words())
}

/// A handle holds its object: the last close lets a thread and a process
/// go back to their pools, and a closed handle is bad from then on.
pub fn closing_a_handle_releases_its_object(_: &Boot) -> Result<(), &'static str> {
    let (processes, threads) = (process::in_use(), thread::in_use());
    with_caller(|c| {
        let other = process::create(LIMIT, CEILING).map_err(|_| "no second process")?;
        let t = match thread::create(other, USER_VA, USER_VA, 0, 10, Policy::Fifo) {
            Ok(t) => t,
            Err(_) => {
                // SAFETY: the process is the test's, and nothing uses it afterwards.
                unsafe { process::release(other) };
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
            thread::release(t);
            process::release(other);
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
        thread::in_use() == threads + 1,
        "the last handle to a thread closed, and the thread stayed",
    )?;
    c.fails(n, &[ht.0], Error::BadHandle)?;
    c.succeeds(n, &[hp.0], &[])?;
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
        t.base_priority == 20
            && t.sched.priority() == 20
            && t.sched.policy() == Policy::RoundRobin
            && t.sched.state() == State::Stopped,
        "a stopped thread did not take its new priority and policy",
    )?;
    // A thread that ended: BAD_STATE, which comes after the ceilings.
    sched::start(low).map_err(|_| "the thread did not start")?;
    // SAFETY: the test holds its own reference to the thread.
    unsafe { sched::exit(low) };
    c.fails(n, &[to_low, 21, fifo], Error::AccessDenied)?;
    c.fails(n, &[to_low, 20, fifo], Error::BadState)
}

/// process_create checks the values first, then the exit channel, then
/// the ceiling against the caller's (spec 11); a good call returns a handle
/// with the owner's rights to a live process with the ceiling given. With
/// the caller's table full it fails with LIMIT_REACHED, and the new process
/// goes again. The caller's ceiling is 30.
pub fn process_create_checks_its_arguments(_: &Boot) -> Result<(), &'static str> {
    let processes = process::in_use();
    let c = Caller::with_ceiling(30)?;
    let result = process_create_cases(&c);
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
        c.fails(n, &[quota, limit, ceiling, 0, 0], Error::InvalidArgs)?;
        // Values come before handles.
        c.fails(n, &[quota, limit, ceiling, closed, 5], Error::InvalidArgs)?;
    }
    // A notification priority without a channel, a channel without one.
    c.fails(n, &[page, 16, 20, 0, 5], Error::InvalidArgs)?;
    c.fails(n, &[page, 16, 20, closed, 0], Error::InvalidArgs)?;
    c.fails(n, &[page, 16, 20, closed, 5], Error::BadHandle)?;
    // No object is a channel before milestone 1.3.
    c.fails(n, &[page, 16, 20, resource, 5], Error::WrongType)?;
    // Handles come before the ceiling.
    c.fails(n, &[page, 16, 31, closed, 5], Error::BadHandle)?;
    c.fails(n, &[page, 16, 31, 0, 0], Error::AccessDenied)?;
    let child = c.created(n, &[page, 16, 30, 0, 0])?;
    // SAFETY: the caller's process is the test's.
    let found = unsafe { c.process.as_ref() }.lookup(child, OWNER_RIGHTS, Object::process);
    // SAFETY: the handle holds the child.
    let good = found.is_ok_and(|p| unsafe {
        p != c.process && p.as_ref().ceiling() == 30 && p.as_ref().state() == ProcessState::Alive
    });
    c.close(child)?;
    check(
        good,
        "the handle does not name a live child with the owner's rights and its ceiling",
    )?;
    full_table_cases(c, n)
}

/// A full table of the caller: LIMIT_REACHED, and the new process goes.
fn full_table_cases(c: &Caller, n: u16) -> Result<(), &'static str> {
    let processes = process::in_use();
    with_full_table(c, n, &[PAGE_SIZE, 16, 30, 0, 0])?;
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
    check(
        process::translate(low, BUFFER as usize).is_none(),
        "the buffer's page outlived its thread",
    )?;
    // A full table of the caller: LIMIT_REACHED, and the new thread and
    // its buffer go; the buffer's page tables stay with the process.
    let (threads, frames) = (thread::in_use(), phys::free_frames());
    with_full_table(c, n, &good(to_low, 20))?;
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
            && t.base_priority == 20
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
/// thread leaves the queue, a stopped one ends where it is (spec 11).
/// The process's space and its threads' buffers go at once; handles keep
/// the shells, and object_info reports «killed». Killing it again
/// succeeds; thread_start, thread_create and thread_set_priority find it
/// and its threads ended (BAD_STATE). thread_start and process_kill check
/// their handles first. A running thread's case is `process_kills_itself`
/// at EL0.
pub fn process_kill_ends_threads_in_every_state(_: &Boot) -> Result<(), &'static str> {
    let (processes, threads) = (process::in_use(), thread::in_use());
    with_caller(kill_cases)?;
    check(
        process::in_use() == processes && thread::in_use() == threads,
        "the test's processes or threads stayed in their pools",
    )
}

fn kill_cases(c: &Caller) -> Result<(), &'static str> {
    let child = c.created(Call::ProcessCreate.number(), &[PAGE_SIZE, 16, 20, 0, 0])?;
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
    // Four tables (levels 0-3 over both buffers) and two buffers.
    check(
        phys::free_frames() == frames + 6,
        "the killed process kept its tables or its threads' buffers",
    )?;
    // SAFETY: the handles hold the threads.
    let dead = unsafe { [tr, ts].map(|t| t.as_ref().sched.state() == State::Dead) };
    check(
        dead == [true, true] && sched::first(10).is_none(),
        "a thread of the killed process did not end",
    )?;
    let info = Call::ObjectInfo.number();
    let killed = ProcessState::Killed.to_words();
    c.succeeds(info, &[child.0, INFO_PROCESS_STATE, 0], &killed)?;
    c.succeeds(kill, &[child.0], &[])?;
    c.fails(start, &[stopped.0], Error::BadState)?;
    let args = thread_args(child.0, USER_VA as u64, USER_VA as u64, 10, FIFO, BUFFER);
    c.fails(Call::ThreadCreate.number(), &args, Error::BadState)?;
    let set = Call::ThreadSetPriority.number();
    c.fails(set, &[ready.0, 10, FIFO], Error::BadState)
}
