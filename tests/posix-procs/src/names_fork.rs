// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A fork in the middle of an operation on names. Run in a child of the
//! loader, which can fork (a program that init started cannot).
use super::names_stages::*;
use core::ffi::c_int;

unsafe extern "C" {
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(code: c_int) -> !;
}

const EIO: c_int = 5;

static STEPS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static FORKED: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-2);
static MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The fork in the middle of an operation. Mode 0: at the fifth Step of the
/// rename the process forks. Mode 1: the reply of the Start is lost, and the
/// process forks before the Start goes again. The child finds the record of
/// the operation dropped and answers EIO without another request; the job
/// belongs to the parent, whose rename ends with success, once.
fn fork_hook(kind: posix_abi::change::Probe) -> bool {
    use core::sync::atomic::Ordering::SeqCst;
    use posix_abi::change::Probe;
    match (MODE.load(SeqCst), kind) {
        (0, Probe::Step) if STEPS.fetch_add(1, SeqCst) == 4 => {
            // SAFETY: the C function of relibc.
            FORKED.store(unsafe { fork() }, SeqCst);
            false
        }
        (1, Probe::Start) if FORKED.load(SeqCst) == -2 => {
            // SAFETY: the C function of relibc.
            FORKED.store(unsafe { fork() }, SeqCst);
            // The parent and the child both lose the reply of the Start.
            true
        }
        _ => false,
    }
}

/// One fork in the middle of the rename of the big directory.
fn fork_once(mode: u32, line: i32) -> Result<(), i32> {
    use core::sync::atomic::Ordering::SeqCst;
    ok(files_names_big(), line)?;
    STEPS.store(0, SeqCst);
    FORKED.store(-2, SeqCst);
    MODE.store(mode, SeqCst);
    posix_abi::change::probe_hook(Some(fork_hook));
    let answer = slow_rename();
    posix_abi::change::probe_hook(None);
    let forked = FORKED.load(SeqCst);
    if forked == 0 {
        // The child: EIO, and nothing of the operation sent after it.
        // SAFETY: relibc's _exit.
        unsafe { _exit(if answer == EIO { 0 } else { 100 + answer }) };
    }
    check(forked > 0, line + 1)?;
    let mut status = 0;
    // SAFETY: relibc's waitpid and a live int.
    let waited = unsafe { waitpid(forked, &mut status, 0) };
    check(waited == forked, line + 2)?;
    // The child exited with code 0: its answer was EIO.
    check(status == 0, line + 3)?;
    // The parent's rename succeeded, once: the name moved and stays moved.
    check(answer == 0, line + 4)?;
    check(
        is(b"/tmp/big/n", REG) && absent(&big_name(BIG - 1)),
        line + 5,
    )?;
    // The job of the parent was released: places and keys are free.
    for _ in 0..20 {
        ok(slow_rename(), line + 6)?;
    }
    ok(files_names_big_gone(), line + 7)
}

/// Run in a child of the loader, which can fork.
#[unsafe(no_mangle)]
pub extern "C" fn files_names_fork_in_flight() -> i32 {
    fork_once(0, 420)
        .and_then(|()| fork_once(1, 430))
        .err()
        .unwrap_or(0)
}

/// How many requests of the operations on names the kernel took back from
/// the queue of the service because a signal came (names-signal.c reads it).
#[unsafe(no_mangle)]
pub extern "C" fn files_names_interrupted() -> u32 {
    posix_abi::change::interrupted_requests()
}
