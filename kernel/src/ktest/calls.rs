// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Kernel tests of the system calls (spec 11, 12). The kernel makes each
//! call for a thread that never runs, as if the thread had made it, and
//! checks every register the call may write: on an error only x0 changes,
//! on success x0 is 0 and the values follow in x1 and up. The same calls
//! from EL0 are in `el0`.

use super::check;
use crate::boot::Boot;
use crate::object::Object;
use crate::process::{self, Process};
use crate::syscall;
use crate::thread::{self, Policy, Thread};
use abi::{
    Call, Error, Handle, INFO_PROCESS_STATE, INIT_BOOT_IMAGE, INIT_PROCESS, INIT_RESOURCE,
    INIT_RESOURCE_RIGHTS, INIT_THREAD, OWNER_RIGHTS, ProcessState, Rights,
};
use core::ptr::NonNull;

/// The line `debug_write_checks_its_arguments` prints: 64 bytes, all of
/// x2-x9. xtask looks for it in the output.
const LINE: &[u8; 64] = b"kernel test: debug_write prints all 64 bytes of x2-x9 in order.\n";
/// A line the same test prints with `#` past its length in x2-x9, then a
/// newline; xtask wants it whole.
const STOPS: &[u8] = b"debug_write stops at its length";

const LIMIT: u32 = 16;
const USER_VA: usize = 0x40_0000;

/// A process with a thread that never runs; the kernel makes calls for it.
struct Caller {
    process: NonNull<Process>,
    thread: NonNull<Thread>,
}

impl Caller {
    fn new() -> Result<Caller, &'static str> {
        let process = process::create(LIMIT).map_err(|_| "no process")?;
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
        want[0] = error as u64;
        self.expect(number, args, want)
    }

    /// The call succeeds with `values` in x1 and up and changes nothing else.
    fn succeeds(&self, number: u16, args: &[u64], values: &[u64]) -> Result<(), &'static str> {
        let mut want = with_marks(args);
        want[0] = 0;
        want[1..=values.len()].copy_from_slice(values);
        self.expect(number, args, want)
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
        let other = process::create(LIMIT).map_err(|_| "no second process")?;
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
