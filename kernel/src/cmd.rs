// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Commands between CPUs (SMP stage 4, decision 1): the state of a thread's
//! scheduling belongs to the CPU the thread runs on (`thread::cpu_of`), and
//! only that CPU changes it. Another CPU that needs a change posts a command
//! for the thread: a flag in the thread (`WAKE`, `START`, `UNPARK`, `LEVEL`,
//! `BOOST`, `EXIT`), the arguments in the thread's own words, and the thread
//! in the queue "CPU i to CPU j" of the sender, then an SGI. A queue has one
//! writer and one reader and never waits: a thread stands in the queues once
//! at most (the flags are set at the first command only, and the reader
//! clears them when it takes the thread), so THREADS places are enough and
//! a full queue cannot happen.
//!
//! A section posts into the CPU's outbox (`post`); the outbox is sent at
//! the top of the loop of the way out of the kernel (`flush`), after the
//! copy of a message that a woken thread reads (thread::flush_copy), and
//! after the section under OBJ ended: the SGI is no part of its hold. The
//! owner takes the commands where it handles the SGI (`drain`), on an empty
//! kernel stack, and serves each thread's flags in a fixed order.

use crate::arch::cpu::{self, MAX_CPUS};
use crate::arch::gic;
use crate::local::local;
use crate::thread::{self, THREADS, Thread};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use kcore::gic::SGI_CMD;

/// The thread waits and its wait ended (Scheduler::wake).
pub const WAKE: u8 = 1;
/// The thread started (Scheduler::start); the kernel's reference is held.
pub const START: u8 = 2;
/// The thread leaves the parked list of its process (Scheduler::unpark).
pub const UNPARK: u8 = 4;
/// A new base priority or policy (`ask_level`).
pub const LEVEL: u8 = 8;
/// A boost to a level (`ask_boost`).
pub const BOOST: u8 = 16;
/// The thread ends (`ask_exit`).
pub const EXIT: u8 = 32;

/// The arguments of the commands LEVEL, BOOST and EXIT, by thread number: a
/// plain store each, whose last value stands, and that the owner takes with a
/// swap. A thread keeps its number until its EXIT is served.
struct Asked {
    level: AtomicU16,
    boost: AtomicU16,
    exit: AtomicU16,
}

static ASKED: [Asked; THREADS] = [const {
    Asked {
        level: AtomicU16::new(0),
        boost: AtomicU16::new(0),
        exit: AtomicU16::new(0),
    }
}; THREADS];

fn asked<'a>(t: NonNull<Thread>) -> &'a Asked {
    &ASKED[usize::from(thread::index(t))]
}

/// The new priority and policy asked of `t`, a word of `pack_level`.
pub fn ask_level(t: NonNull<Thread>, word: u16) {
    asked(t).level.store(word, Ordering::Relaxed);
}

/// The boost asked of `t`: the larger of two asks stands (a boost only
/// raises).
pub fn ask_boost(t: NonNull<Thread>, level: u8, ceiling: u8) {
    let word = &asked(t).boost;
    let ask: u16 = 1 << 12 | u16::from(ceiling) << 6 | u16::from(level);
    let old = word.load(Ordering::Relaxed);
    if old == 0 || (old & 0x3f).min((old >> 6) & 0x3f) < u16::from(level.min(ceiling)) {
        word.store(ask, Ordering::Relaxed);
    }
}

/// The end of `t`: the cause in bits 0-7, bit 8 when the owner drops the
/// kernel's reference.
pub fn ask_exit(t: NonNull<Thread>, held: bool, cause: u8) {
    asked(t).exit.store(
        0x200 | u16::from(held) << 8 | u16::from(cause),
        Ordering::Relaxed,
    );
}

/// What was asked of `t`: priority word, boost word, exit word; each is 0
/// when nothing was.
pub fn take_asked(t: NonNull<Thread>) -> (u16, u16, u16) {
    let a = asked(t);
    (
        a.level.swap(0, Ordering::Relaxed),
        a.boost.swap(0, Ordering::Relaxed),
        a.exit.swap(0, Ordering::Relaxed),
    )
}

/// A timer whose last reference went on this CPU is in the heap of another
/// one, which takes it off (`timer::reap`): the pointer of the timer stands
/// in the queue with bit 0 set.
pub const REAP: u8 = 64;

/// Places in a queue: every thread of the system, once.
const RING: usize = 1024;
const _: () = assert!(THREADS <= RING);

#[repr(align(64))]
struct Line(AtomicU32);

/// The queue from one CPU to another.
struct Ring {
    /// Next place the writer fills, and next the reader takes: on lines of
    /// their own.
    tail: Line,
    head: Line,
    slots: [AtomicUsize; RING],
}

impl Ring {
    const fn new() -> Ring {
        Ring {
            tail: Line(AtomicU32::new(0)),
            head: Line(AtomicU32::new(0)),
            slots: [const { AtomicUsize::new(0) }; RING],
        }
    }

    /// The writer's: `value` is a thread's address, or a timer's with bit 0
    /// set. A thread stands in the queues once at most, but the timers that
    /// other CPUs let go come in any number, so a full queue is waited for:
    /// the writer holds no lock here (`flush`), and the reader needs none to
    /// take the entry.
    fn push(&self, value: usize, to: usize) {
        let tail = self.tail.0.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.head.0.load(Ordering::Acquire)) >= RING as u32 {
            let limit = crate::arch::timer::now() + 2 * crate::arch::timer::frequency();
            while tail.wrapping_sub(self.head.0.load(Ordering::Acquire)) >= RING as u32 {
                assert!(
                    crate::arch::timer::now() < limit,
                    "CPU {to} takes no command: its queue has been full for two seconds"
                );
                gic::send_sgi(to, SGI_CMD);
                core::hint::spin_loop();
            }
        }
        self.slots[tail as usize % RING].store(value, Ordering::Relaxed);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
    }

    /// The reader's.
    fn pop(&self) -> Option<usize> {
        let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) {
            return None;
        }
        let value = self.slots[head as usize % RING].load(Ordering::Relaxed);
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}

/// `RINGS[to][from]`.
static RINGS: [[Ring; MAX_CPUS]; MAX_CPUS] =
    [const { [const { Ring::new() }; MAX_CPUS] }; MAX_CPUS];

/// Commands a section posts, until `flush`: the most that one call, one
/// portion of cleanup or one interrupt makes (the stage Threads takes up to
/// THREADS_PORTION threads, the stage Replies up to REPLIES_PORTION).
pub const OUTBOX: usize = 96;

pub struct Outbox {
    n: usize,
    items: [(usize, u8); OUTBOX],
}

impl Outbox {
    pub const fn new() -> Outbox {
        Outbox {
            n: 0,
            items: [(0, 0); OUTBOX],
        }
    }
}

/// Posts `flag` for `t`, a thread of another CPU, to go out at `flush`.
pub fn post(t: NonNull<Thread>, flag: u8) {
    debug_assert!(thread::cpu_of(t) != cpu::this().index());
    let mut o = local().outbox.lock();
    assert!(
        o.n < OUTBOX,
        "a section posts more commands than the outbox holds"
    );
    let n = o.n;
    o.items[n] = (t.as_ptr() as usize, flag);
    o.n += 1;
    local()
        .deferred
        .fetch_or(crate::local::OUTBOX, Ordering::Relaxed);
}

/// Posts the end of timer `t`, which another CPU's heap holds, for that CPU.
pub fn post_reap(t: NonNull<crate::timer::Timer>) {
    let mut o = local().outbox.lock();
    assert!(
        o.n < OUTBOX,
        "a section posts more commands than the outbox holds"
    );
    let n = o.n;
    o.items[n] = (t.as_ptr() as usize, REAP);
    o.n += 1;
    local()
        .deferred
        .fetch_or(crate::local::OUTBOX, Ordering::Relaxed);
}

/// Asks CPU `to` to enter the kernel, with no command: a thread of it at
/// EL0 is to see what changed in its state (`pending` of an upcall).
pub fn kick(to: usize) {
    debug_assert!(to != cpu::this().index());
    let mut o = local().outbox.lock();
    assert!(
        o.n < OUTBOX,
        "a section posts more commands than the outbox holds"
    );
    let n = o.n;
    o.items[n] = (to, 0);
    o.n += 1;
    local()
        .deferred
        .fetch_or(crate::local::OUTBOX, Ordering::Relaxed);
}

/// `flush` when the outbox holds commands.
#[inline(always)]
pub fn flush_posted() {
    if local().deferred.load(Ordering::Relaxed) & crate::local::OUTBOX != 0 {
        flush();
    }
}

/// Sends what the sections posted: each thread's flag, the thread into the
/// queue to its CPU when it is not in one, and one SGI to each CPU that has
/// something new. Outside OBJ, with the copies of messages made.
#[inline(never)]
pub fn flush() {
    local()
        .deferred
        .fetch_and(!crate::local::OUTBOX, Ordering::Relaxed);
    let me = cpu::this().index();
    let mut mask = 0u32;
    {
        let mut o = local().outbox.lock();
        for i in 0..o.n {
            let (what, flag) = o.items[i];
            if flag == 0 {
                mask |= 1 << what;
                continue;
            }
            if flag == REAP {
                // SAFETY: the timer holds on to its pool and shell until
                // the owner takes it.
                let to = crate::timer::owner_cpu(unsafe {
                    NonNull::new_unchecked(what as *mut crate::timer::Timer)
                });
                RINGS[to][me].push(what | 1, to);
                mask |= 1 << to;
                continue;
            }
            // SAFETY: the kernel's reference keeps the thread of a command.
            let t = unsafe { NonNull::new_unchecked(what as *mut Thread) };
            let to = thread::cpu_of(t);
            // Release: what the section wrote for the owner (the message,
            // the arguments) is there when the owner takes the flag.
            let before = thread_cmds(t).fetch_or(flag, Ordering::Release);
            if before == 0 {
                RINGS[to][me].push(t.as_ptr() as usize, to);
            }
            mask |= 1 << to;
        }
        o.n = 0;
    }
    for to in (0..MAX_CPUS).filter(|c| mask & (1 << c) != 0) {
        gic::send_sgi(to, SGI_CMD);
    }
}

fn thread_cmds<'a>(t: NonNull<Thread>) -> &'a AtomicU8 {
    // SAFETY: the thread is alive and in place; the field is atomic.
    unsafe { &(*t.as_ptr()).numbers.cmds }
}

/// The owner's: takes the commands in the queues to this CPU and serves
/// each thread's flags. On the empty kernel stack, no lock held.
pub fn drain() {
    let me = cpu::this().index();
    for from in (0..crate::smp::cpus()).filter(|&f| f != me) {
        while let Some(value) = RINGS[me][from].pop() {
            if value & 1 != 0 {
                // SAFETY: the sender left the timer to this CPU (`REAP`).
                crate::timer::reap(unsafe {
                    NonNull::new_unchecked((value & !1) as *mut crate::timer::Timer)
                });
                continue;
            }
            // SAFETY: a thread of the queue is alive: the kernel's reference
            // keeps it until its commands are served.
            let t = unsafe { NonNull::new_unchecked(value as *mut Thread) };
            let flags = thread_cmds(t).swap(0, Ordering::Acquire);
            serve(t, flags);
        }
    }
}

/// The flags of `t` in the order that keeps a thread consistent: start,
/// the end of a park, the end of a wait, a new level, the end.
fn serve(t: NonNull<Thread>, flags: u8) {
    use crate::sched;
    if flags & START != 0 {
        sched::serve_start(t);
    }
    if flags & UNPARK != 0 {
        sched::serve_unpark(t);
    }
    if flags & WAKE != 0 {
        sched::serve_wake(t);
    }
    if flags & (LEVEL | BOOST) != 0 {
        sched::serve_level(t);
    }
    if flags & EXIT != 0 {
        sched::serve_exit(t);
    }
}
