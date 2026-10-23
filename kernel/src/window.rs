// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The probes of the windows between the steps of the kernel on several CPUs
//! (feature `window-probe`; `cargo xtask smp-window`, tests/init/src/smp.rs):
//! each waits at a point where the kernel gives another CPU the room to act,
//! and the tests of the test init that follow fill the room. The kernel as it
//! ships has none of this: the points of call stand under the same feature,
//! one line each, and the deliberate breaks (`break-*`) are listed in
//! docs/smp.md.

use crate::arch::cpu;
use crate::cmd::{BOOST, EXIT, WAKE};
use crate::thread::{self, Thread};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The priority of the thread the probe watches: the client of the test.
pub const LEVEL: u8 = 17;

/// The priority of the thread whose state the probe asks for while its
/// wake is on the way.
pub const INFO_LEVEL: u8 = 6;

static INFO_ASKED: AtomicBool = AtomicBool::new(false);

/// In `flush`, the first command WAKE to a thread at INFO_LEVEL: the
/// section that posted it took the thread out of its wait queue, and its
/// CPU has not served the command, so the thread is Waiting with nothing
/// to wait for. object_info gives Ready for it (#438).
fn info_in_flight(t: NonNull<Thread>) {
    // SAFETY: the kernel's reference keeps the thread.
    if unsafe { t.as_ref() }.priority() != INFO_LEVEL || INFO_ASKED.swap(true, Ordering::Relaxed) {
        return;
    }
    let (info, _, _) = thread::info(t);
    if info.state == abi::ThreadState::Ready {
        kprintln!("smp window  thread_info of a thread with its wake on the way gave Ready");
    }
}

static OPENED: AtomicBool = AtomicBool::new(false);
static HOLDING: AtomicBool = AtomicBool::new(false);
static ENDED_INSIDE: AtomicBool = AtomicBool::new(false);

/// In `flush`, before the first command WAKE to a thread at LEVEL goes
/// into its queue once its end is held (`hold_until_replied`): waits
/// until the CPU of the thread saw the reply (2 s at most, for a host
/// that is busy), then 20 ms more, in which that CPU ends the thread,
/// and says whether it did.
pub fn open(t: NonNull<Thread>, flag: u8) {
    if flag == WAKE {
        info_in_flight(t);
    }
    if flag != WAKE || !HOLDING.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: the kernel's reference keeps the thread.
    let level = unsafe { t.as_ref() }.priority();
    if level != LEVEL || OPENED.swap(true, Ordering::Relaxed) {
        return;
    }
    let seen = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
    while !ENDED_INSIDE.load(Ordering::Acquire) && crate::arch::timer::now() < seen {
        core::hint::spin_loop();
    }
    let until = crate::arch::timer::now() + crate::arch::timer::frequency() / 50;
    while crate::arch::timer::now() < until {
        core::hint::spin_loop();
    }
    if ENDED_INSIDE.load(Ordering::Acquire) {
        kprintln!(
            "smp window  a thread ended on its CPU between the post of its command and the flush"
        );
    }
}

/// In the stage Threads of a process, before its threads end: a thread
/// at LEVEL that waits for a reply is let alone until the reply took it
/// out of its wait, 2 s at most (the reply comes a few ms after the kill
/// on a quiet host), so that its end follows the post of the reply.
///
/// # Safety
/// `first` is the thread at the cursor of the stage, which is alive; no
/// section of OBJ is held.
pub unsafe fn hold_until_replied(first: Option<NonNull<Thread>>) {
    let mut next = first;
    while let Some(t) = next {
        // SAFETY: the caller's promise; the list is of live threads.
        let (priority, after) = unsafe {
            (
                t.as_ref().base_priority(),
                (*t.as_ptr()).siblings.and_then(|s| s.next),
            )
        };
        if priority == SERVICE_LEVEL {
            ARMED.store(true, Ordering::Release);
        }
        if priority == LEVEL {
            let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
            let mut held = false;
            loop {
                let waiting = {
                    let _section = crate::obj::lock();
                    thread::waits(t)
                };
                if waiting && !held {
                    held = true;
                    HOLDING.store(true, Ordering::Release);
                }
                if !waiting {
                    if held {
                        ENDED_INSIDE.store(true, Ordering::Release);
                    }
                    break;
                }
                if crate::arch::timer::now() > until {
                    break;
                }
                core::hint::spin_loop();
            }
        }
        next = after;
    }
}

/// In the stage Threads of a process, before its threads end, outside
/// OBJ: while a thread at `kcore::sched::READY_GAP_LEVEL` waits for its
/// timer, the stage waits (2 s at most); once it wakes, 20 us more. Its
/// CPU takes the woken thread off its ready queue, where the build waits
/// inside the removal (`ready-gap`), as the stage reads the link of the
/// thread. This is a CPU that reads the link of a thread of another CPU
/// as it changes (#438).
///
/// # Safety
/// `first` is the thread at the cursor of the stage, which is alive; no
/// section of OBJ is held.
pub unsafe fn hold_until_woken(first: Option<NonNull<Thread>>) {
    let mut next = first;
    let mut woke = false;
    while let Some(t) = next {
        // SAFETY: the caller's promise; the list is of live threads.
        let (priority, after) = unsafe {
            (
                t.as_ref().base_priority(),
                (*t.as_ptr()).siblings.and_then(|s| s.next),
            )
        };
        if priority == kcore::sched::READY_GAP_LEVEL {
            let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
            loop {
                let waiting = {
                    let _section = crate::obj::lock();
                    thread::waits(t)
                };
                if !waiting || crate::arch::timer::now() > until {
                    break;
                }
                core::hint::spin_loop();
            }
            woke = true;
        }
        next = after;
    }
    if woke {
        let later = crate::arch::timer::now() + crate::arch::timer::frequency() / 200_000;
        while crate::arch::timer::now() < later {
            core::hint::spin_loop();
        }
    }
}

/// The priority of the thread whose timer_create the probe holds
/// between its entry and its section.
pub const ENTRY_LEVEL: u8 = 7;

/// In `dispatch`, before the section of a timer_create: a caller at
/// ENTRY_LEVEL waits, with no section, up to 200 us for its process to
/// end, so that the call takes `OBJ` after the end of the process it
/// writes into (#438). The wait is short for the calls of the thread
/// that come before the end.
pub fn entry_gap(t: NonNull<Thread>) {
    // SAFETY: the caller is the running thread.
    if unsafe { t.as_ref() }.priority() != ENTRY_LEVEL {
        return;
    }
    // SAFETY: as above.
    let process = unsafe { t.as_ref() }.process();
    let until = crate::arch::timer::now() + crate::arch::timer::frequency() / 5_000;
    while crate::process::alive_unlocked(process) && crate::arch::timer::now() < until {
        core::hint::spin_loop();
    }
}

/// The priority of the service the boost probe watches: the process of
/// the test's service.
pub const SERVICE_LEVEL: u8 = 15;
static ARMED: AtomicBool = AtomicBool::new(false);
static TAKEN: AtomicBool = AtomicBool::new(false);
static LEFT_ALONE: AtomicBool = AtomicBool::new(false);

fn is_service(t: NonNull<Thread>) -> bool {
    // SAFETY: the callers hold the thread: the kernel's reference keeps
    // it until its commands are served.
    // The level it was given: a client raised from another CPU boosts it
    // before its process ends, and the probe holds its end all the same.
    unsafe { t.as_ref() }.base_priority() == SERVICE_LEVEL
}

/// In `drain`, right after the owner took the flags of `t`: the first
/// EXIT of a thread at SERVICE_LEVEL waits 150 ms before it is served,
/// with the thread let go (`mark_ended`) and its number kept, in which
/// a boost from the chain of requests of another CPU finds it.
pub fn taken(t: NonNull<Thread>, flags: u8) {
    if flags & EXIT == 0 || !is_service(t) || TAKEN.swap(true, Ordering::Relaxed) {
        return;
    }
    kprintln!("smp window  the end of a service is held for 150 ms");
    let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 3 / 20;
    while crate::arch::timer::now() < until {
        core::hint::spin_loop();
    }
}

/// At the end of the stage Threads of the process that had a thread at
/// SERVICE_LEVEL, no section held: its clients stay in their wait for
/// 400 ms, in which the test raises them from other CPUs.
pub fn hold_replies() {
    if ARMED.swap(false, Ordering::Acquire) {
        let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2 / 5;
        while crate::arch::timer::now() < until {
            core::hint::spin_loop();
        }
    }
}

/// In `post`, under OBJ: a boost posted for a thread at SERVICE_LEVEL
/// that the scheduler let go would stand in the queue past the release
/// of the thread.
pub fn posted(t: NonNull<Thread>, flag: u8) {
    if flag & BOOST != 0 && is_service(t) && !thread::is_held(t) {
        panic!("a boost was posted for a thread that the scheduler let go");
    }
}

/// In `sched::boost`: a boost of a thread of another CPU that the
/// scheduler let go was left alone.
pub fn boost_left_alone(t: NonNull<Thread>) {
    if is_service(t) && !LEFT_ALONE.swap(true, Ordering::Relaxed) {
        kprintln!("smp window  a boost of a thread that ended on its CPU was left alone");
    }
}

/// The priority of the thread whose receive or send the probe holds
/// before its section, until a request for its entry was made.
pub const WAIT_LEVEL: u8 = 14;
/// The priority of the receiver whose section `break-one-section` splits
/// in two.
#[cfg(feature = "break-one-section")]
pub const HEAD_LEVEL: u8 = 13;

/// In `dispatch` of send and receive, before the section: a thread at
/// WAIT_LEVEL that has no request yet waits, with no section, until
/// another CPU made one. The request finds no wait to end
/// (thread_upcall_request answers Ok), and the look under OBJ before the
/// wait has to find it.
pub fn after_check(t: NonNull<Thread>) {
    // SAFETY: the caller is the running thread.
    let upcall = unsafe { &t.as_ref().upcall };
    // SAFETY: as above.
    if unsafe { t.as_ref() }.base_priority() == WAIT_LEVEL && !upcall.is_pending() {
        let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
        while !upcall.is_pending() && crate::arch::timer::now() < until {
            core::hint::spin_loop();
        }
    }
}

/// In receive, after the room for the handles of the request at the
/// head was made (`break-one-section`): a receiver at HEAD_LEVEL gives
/// OBJ back and takes it again, which a receive in one section never
/// does. The number of the section catches it.
#[cfg(feature = "break-one-section")]
pub fn split_section(t: NonNull<Thread>) {
    // SAFETY: the caller is the running thread.
    if unsafe { t.as_ref() }.base_priority() == HEAD_LEVEL {
        crate::obj::split_section();
    }
}

/// The priority of the caller of a suspension that the probe holds a
/// CPU back for.
pub const LAG_LEVEL: u8 = 19;
/// The CPU the probe holds back.
const LAG_CPU: usize = 1;

static LAG: AtomicBool = AtomicBool::new(false);

/// A suspension (process_control) by a thread at LAG_LEVEL begins: the
/// next quiescent point of CPU 1 comes 20 ms late.
pub fn arm_lag(t: NonNull<Thread>) {
    // SAFETY: the caller is the running thread.
    if unsafe { t.as_ref() }.priority() == LAG_LEVEL {
        LAG.store(true, Ordering::Release);
    }
}

/// At the start of a quiescent point (qsbr::quiesce).
pub fn lag() {
    if cpu::this().index() == LAG_CPU && LAG.swap(false, Ordering::Acquire) {
        let until = crate::arch::timer::now() + crate::arch::timer::frequency() / 50;
        while crate::arch::timer::now() < until {
            core::hint::spin_loop();
        }
    }
}

/// The priority of the caller of mem_map that the probe watches: the
/// time between its two sections is 1 ms, and it counts the passes of
/// its checks.
pub const GAP_LEVEL: u8 = 16;
/// Calls of mem_map at GAP_LEVEL the probe counts before it speaks.
const GAP_CALLS: u32 = 20;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static MOST: AtomicU32 = AtomicU32::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);

fn watched() -> bool {
    crate::sched::running()
        // SAFETY: the running thread is alive.
        .is_some_and(|t| unsafe { t.as_ref() }.priority() == GAP_LEVEL)
}

/// The priority of the thread whose mem_map RX waits, in its portion
/// outside OBJ, for the end of the process it maps into (`exec_gap`).
pub const EXEC_LEVEL: u8 = 12;

/// In the portion of a mem_map or mem_protect that makes pages
/// executable, outside OBJ (process::exec_frames): a thread at
/// EXEC_LEVEL waits up to 2 s until another CPU killed `target`, so that
/// the portion takes OBJ again with its process ended.
pub fn exec_gap(target: NonNull<crate::process::Process>) {
    let at_level = crate::sched::running()
        // SAFETY: the running thread is alive.
        .is_some_and(|t| unsafe { t.as_ref() }.priority() == EXEC_LEVEL);
    if !at_level {
        return;
    }
    let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
    while crate::process::alive_unlocked(target) && crate::arch::timer::now() < until {
        core::hint::spin_loop();
    }
}

/// The priority of the caller of process_create that the probe holds
/// between its two sections (`spawn_gap`).
pub const SPAWN_LEVEL: u8 = 11;

/// The process whose caller of process_create waits in `spawn_gap`, as
/// an address, 0 for none, and how many handles of it were closed.
static WATCHED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static CLOSED: AtomicU32 = AtomicU32::new(0);

/// A handle_close of a thread of `process` succeeded.
pub fn closed(process: NonNull<crate::process::Process>) {
    if WATCHED.load(Ordering::Acquire) == process.as_ptr() as usize {
        CLOSED.fetch_add(1, Ordering::Release);
    }
}

/// Between the two sections of process_create, no section held: a
/// caller at SPAWN_LEVEL waits up to 2 s until another thread of its
/// process closed a handle or the process ended, so that the second
/// section finds the arguments changed.
pub fn spawn_gap(t: NonNull<Thread>, _child: NonNull<crate::process::Process>) {
    // SAFETY: the caller is the running thread.
    if unsafe { t.as_ref() }.priority() != SPAWN_LEVEL {
        return;
    }
    // SAFETY: as above.
    let process = unsafe { t.as_ref() }.process();
    let seen = CLOSED.load(Ordering::Acquire);
    WATCHED.store(process.as_ptr() as usize, Ordering::Release);
    let until = crate::arch::timer::now() + crate::arch::timer::frequency() * 2;
    while CLOSED.load(Ordering::Acquire) == seen
        && crate::process::alive_unlocked(process)
        && crate::arch::timer::now() < until
    {
        core::hint::spin_loop();
    }
    WATCHED.store(0, Ordering::Release);
    if !crate::process::alive_unlocked(process) {
        if !SAW_END.swap(true, Ordering::Relaxed) {
            kprintln!("smp window  a process_create waited for the end of its caller");
        }
    } else if CLOSED.load(Ordering::Acquire) != seen && !SAW_CLOSE.swap(true, Ordering::Relaxed) {
        kprintln!("smp window  a process_create waited for a handle to be closed");
    }
}

static SAW_END: AtomicBool = AtomicBool::new(false);
static SAW_CLOSE: AtomicBool = AtomicBool::new(false);

/// A mem_map begins (syscall::mem::change_map).
pub fn map_begins() {
    if watched() {
        CHECKS.store(0, Ordering::Relaxed);
    }
}

/// The checks of a mem_map ran (process::check_free).
pub fn map_checked() {
    if watched() {
        CHECKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Between the two sections of a mem_map: 1 ms, in which the CPUs that
/// make calls on the same process get their sections.
pub fn map_gap() {
    if watched() {
        let until = crate::arch::timer::now() + crate::arch::timer::frequency() / 1000;
        while crate::arch::timer::now() < until {
            core::hint::spin_loop();
        }
    }
}

/// A mem_map ended its sections: after GAP_CALLS calls the probe says how
/// many passes of the checks the worst call needed.
pub fn map_ends() {
    if watched() {
        MOST.fetch_max(CHECKS.load(Ordering::Relaxed), Ordering::Relaxed);
        if CALLS.fetch_add(1, Ordering::Relaxed) + 1 == GAP_CALLS {
            kprintln!(
                "smp window  {GAP_CALLS} mem_map calls, the most passes of the checks in one: {}",
                MOST.load(Ordering::Relaxed)
            );
        }
    }
}
