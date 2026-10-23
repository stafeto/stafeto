// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Commands between CPUs (SMP stage 4, decision 1): the state of a thread's
//! scheduling belongs to the CPU the thread runs on (`thread::cpu_of`), and
//! only that CPU changes it. Another CPU that needs a change posts a command
//! for the thread: a flag in the thread (`WAKE`, `START`, `UNPARK`, `LEVEL`,
//! `BOOST`, `EXIT`), the arguments in the thread's own words, and the thread
//! in the queue "CPU i to CPU j" of the sender, then an SGI. A queue has one
//! writer and one reader and never waits: a thread stands in the queues once
//! at most (the reader clears the flags when it takes the thread, and the
//! first command after that puts the thread in a queue again), so THREADS
//! places are enough and a full queue cannot happen.
//!
//! A section posts into the CPU's outbox (`post`): the flag goes into the
//! thread inside the section, under OBJ, so that the owner's own end of the
//! thread sees a command on its way (`pending`) and hands the kernel's
//! reference to the command (`sched::exit`). The outbox is sent at the top
//! of the loop of the way out of the kernel (`flush`), after the copy of a
//! message that a woken thread reads (thread::flush_copy), and after the
//! section under OBJ ended: the thread goes into the queue and the SGI is no
//! part of its hold. The owner takes the commands where it handles the SGI
//! (`drain`), on an empty kernel stack, and serves each thread's flags in a
//! fixed order, up to DRAIN_BATCH threads in one section; a thread that
//! ended meanwhile is skipped, and a woken thread waits for the copy of its
//! message first (`drain`).

use crate::arch::cpu::{self, MAX_CPUS};
use crate::arch::gic;
use crate::local::local;
use crate::thread::{self, THREADS, Thread};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

/// The arguments of the commands LEVEL, BOOST and EXIT, by thread number,
/// three words of 16 bits in one: the last value of each stands. Every
/// access is in a section under OBJ (the asker's, the owner's `serve_level`
/// and `serve_exit`, the end of the number's thread), so plain loads and
/// stores do. A thread keeps its number until its EXIT is served.
static ASKED: [AtomicU64; THREADS] = [const { AtomicU64::new(0) }; THREADS];

const LEVEL_SHIFT: u32 = 0;
const BOOST_SHIFT: u32 = 16;
const EXIT_SHIFT: u32 = 32;
const WORD: u64 = 0xffff;

fn asked<'a>(t: NonNull<Thread>) -> &'a AtomicU64 {
    crate::obj::assert_held();
    &ASKED[usize::from(thread::index(t))]
}

fn put(t: NonNull<Thread>, shift: u32, word: u16) {
    let a = asked(t);
    let all = a.load(Ordering::Relaxed);
    a.store(
        all & !(WORD << shift) | u64::from(word) << shift,
        Ordering::Relaxed,
    );
}

fn peek(t: NonNull<Thread>, shift: u32) -> u16 {
    ((asked(t).load(Ordering::Relaxed) >> shift) & WORD) as u16
}

/// The new priority and policy asked of `t`, a word of `pack_level`.
pub fn ask_level(t: NonNull<Thread>, word: u16) {
    put(t, LEVEL_SHIFT, word);
}

/// The boost asked of `t`: the larger of two asks stands (a boost only
/// raises).
pub fn ask_boost(t: NonNull<Thread>, level: u8, ceiling: u8) {
    let ask: u16 = 1 << 12 | u16::from(ceiling) << 6 | u16::from(level);
    let old = peek(t, BOOST_SHIFT);
    if old == 0 || (old & 0x3f).min((old >> 6) & 0x3f) < u16::from(level.min(ceiling)) {
        put(t, BOOST_SHIFT, ask);
    }
}

/// The end of `t`: the cause in bits 0-7, bit 8 when the owner drops the
/// kernel's reference.
pub fn ask_exit(t: NonNull<Thread>, held: bool, cause: u8) {
    put(
        t,
        EXIT_SHIFT,
        0x200 | u16::from(held) << 8 | u16::from(cause),
    );
}

/// What was asked of `t` as a new level: priority word, boost word; each is
/// 0 when nothing was. The ask of the end stays.
pub fn take_level(t: NonNull<Thread>) -> (u16, u16) {
    let level = peek(t, LEVEL_SHIFT);
    let boost = peek(t, BOOST_SHIFT);
    put(t, LEVEL_SHIFT, 0);
    put(t, BOOST_SHIFT, 0);
    (level, boost)
}

/// What was asked of `t` as its end: 0 when nothing was.
pub fn take_exit(t: NonNull<Thread>) -> u16 {
    let word = peek(t, EXIT_SHIFT);
    put(t, EXIT_SHIFT, 0);
    word
}

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

    /// The writer's: `value` is a thread's address. A thread stands in the
    /// queues once at most, so a queue of THREADS places is never full, and
    /// the writer never waits (the dying timers go by a chain under OBJ,
    /// timer::reap).
    fn push(&self, value: usize) {
        let tail = self.tail.0.load(Ordering::Relaxed);
        assert!(
            tail.wrapping_sub(self.head.0.load(Ordering::Acquire)) < RING as u32,
            "a queue of commands is full: a thread stands in it twice"
        );
        self.slots[tail as usize % RING].store(value, Ordering::Relaxed);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
    }

    /// Whether the reader has nothing to take.
    fn is_empty(&self) -> bool {
        self.head.0.load(Ordering::Relaxed) == self.tail.0.load(Ordering::Acquire)
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

/// The outbox item of a thread that goes into the queue to its CPU, with the
/// flag that found it in none.
const PUSH: u8 = 128;

/// Whether commands of `t` are on their way to its CPU: set, and not yet
/// taken by the owner. Read on the owner, under OBJ.
pub fn pending(t: NonNull<Thread>) -> bool {
    thread_cmds(t).load(Ordering::Relaxed) != 0
}

/// Posts `flag` for `t`, a thread of another CPU, under OBJ: the flag goes
/// into the thread now, and the thread into the queue to its CPU at `flush`
/// when no command stood there before (the one that did puts it in). The
/// owner's own end of a thread with a command on its way sets `EXIT` the
/// same way. The kernel's reference keeps the thread until the owner
/// serves the commands.
pub fn post(t: NonNull<Thread>, flag: u8) {
    crate::obj::assert_held();
    // Release: what the section wrote for the owner (the arguments, the
    // delivered message) is there when the owner takes the flag.
    #[cfg(feature = "window-probe")]
    crate::window::posted(t, flag);
    let before = thread_cmds(t).fetch_or(flag, Ordering::Release);
    if before != 0 {
        return;
    }
    debug_assert!(thread::cpu_of(t) != cpu::this().index());
    add(t.as_ptr() as usize, PUSH | flag);
}

/// Asks CPU `to` to enter the kernel, with no command: a thread of it at
/// EL0 is to see what changed in its state (`pending` of an upcall), or a
/// dying timer waits for it (timer::reap).
pub fn kick(to: usize) {
    debug_assert!(to != cpu::this().index());
    add(to, 0);
}

/// Puts an item in the outbox: a thread with its flags, or a CPU with 0.
fn add(what: usize, flag: u8) {
    let mut o = local().outbox.lock();
    assert!(
        o.n < OUTBOX,
        "a section posts more commands than the outbox holds"
    );
    let n = o.n;
    o.items[n] = (what, flag);
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

/// Sends what the sections posted: each thread into the queue to its CPU,
/// and one SGI to each CPU that has something new. Outside OBJ, with the
/// copies of messages made.
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
            debug_assert!(flag & PUSH != 0);
            // SAFETY: the kernel's reference keeps the thread of a command
            // until the owner serves it, and the owner takes it from this
            // queue.
            let t = unsafe { NonNull::new_unchecked(what as *mut Thread) };
            #[cfg(feature = "window-probe")]
            crate::window::open(t, flag & !PUSH);
            let to = thread::cpu_of(t);
            RINGS[to][me].push(t.as_ptr() as usize);
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

/// The threads one SGI serves, in one section under OBJ, with the dying
/// timers that fill the rest of the places: one take of OBJ between two
/// polls for an interrupt (decision 3 of the SMP design).
pub const DRAIN_BATCH: usize = 8;

/// The owner's, where it handles the SGI: takes up to DRAIN_BATCH threads
/// from the queues to this CPU, one from each queue in turn (`take_batch`),
/// and serves each thread's flags in one section, after the copies of the
/// messages of the woken ones (`serve_batch`). What is left waits for the
/// SGI this CPU sends itself, which the next poll for an interrupt takes. On
/// the empty kernel stack, no lock held.
pub fn drain() {
    let (batch, n) = take_batch();
    serve_batch(&batch[..n]);
}

/// The threads one SGI serves, with the flags they carried: up to
/// DRAIN_BATCH of the queues to this CPU, one from each queue in turn. Reads
/// the rings and the flags of the threads, takes no lock.
fn take_batch() -> ([(NonNull<Thread>, u8); DRAIN_BATCH], usize) {
    let me = cpu::this().index();
    let cpus = crate::smp::cpus();
    let mut batch = [(NonNull::<Thread>::dangling(), 0u8); DRAIN_BATCH];
    let mut n = 0;
    'take: loop {
        let before = n;
        for from in (0..cpus).filter(|&f| f != me) {
            if n == DRAIN_BATCH {
                break 'take;
            }
            if let Some(value) = RINGS[me][from].pop() {
                // SAFETY: a thread of the queue is alive: the kernel's
                // reference keeps it until its commands are served.
                let t = unsafe { NonNull::new_unchecked(value as *mut Thread) };
                let flags = thread_cmds(t).swap(0, Ordering::Acquire);
                #[cfg(feature = "window-probe")]
                crate::window::taken(t, flags);
                batch[n] = (t, flags);
                n += 1;
            }
        }
        if n == before {
            break;
        }
    }
    (batch, n)
}

/// Serves the flags of the threads of `batch` in one section, with the
/// dying timers that fill the rest of its places: one take of OBJ between
/// two polls for an interrupt (decision 3 of the SMP design). Reads no ring:
/// the kernel tests hand it a full batch of their own.
pub fn serve_batch(batch: &[(NonNull<Thread>, u8)]) {
    let me = cpu::this().index();
    let cpus = crate::smp::cpus();
    let n = batch.len();
    if n == 0 && !crate::timer::reaps_waiting() {
        return;
    }
    // A woken thread reads its message: the copy of the CPU that woke it
    // comes after the flag, takes the time of 960 bytes and needs no OBJ.
    for &(t, flags) in batch {
        if flags & WAKE != 0 {
            thread::wait_copies(t);
        }
    }
    let timers_left = serve_all(batch);
    // A batch that was not full left the queues empty, and each later push
    // comes with an SGI of its own.
    if timers_left || n == DRAIN_BATCH && (0..cpus).any(|f| f != me && !RINGS[me][f].is_empty()) {
        gic::send_sgi(me, SGI_CMD);
    }
}

/// The section of `serve_batch`: the flags of every thread of `batch`, and
/// the dying timers that fill the rest of the places. True when timers are
/// left.
#[inline(never)]
fn serve_all(batch: &[(NonNull<Thread>, u8)]) -> bool {
    crate::obj::serving(crate::obj::ENTRY_DRAIN);
    let _section = crate::obj::lock();
    for &(t, flags) in batch {
        serve(t, flags);
    }
    crate::timer::reap(DRAIN_BATCH - batch.len())
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
