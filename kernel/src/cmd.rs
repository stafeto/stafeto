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
    window::posted(t, flag);
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
            window::open(t, flag & !PUSH);
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
/// from the queues to this CPU, one from each queue in turn, and serves each
/// thread's flags in one section, after the copies of the messages of the
/// woken ones. What is left waits for the SGI this CPU sends itself, which
/// the next poll for an interrupt takes. On the empty kernel stack, no lock
/// held.
pub fn drain() {
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
                window::taken(t, flags);
                batch[n] = (t, flags);
                n += 1;
            }
        }
        if n == before {
            break;
        }
    }
    if n == 0 && !crate::timer::reaps_waiting() {
        return;
    }
    // A woken thread reads its message: the copy of the CPU that woke it
    // comes after the flag, takes the time of 960 bytes and needs no OBJ.
    for &(t, flags) in &batch[..n] {
        if flags & WAKE != 0 {
            thread::wait_copies(t);
        }
    }
    let timers_left = {
        let _section = crate::obj::lock();
        for &(t, flags) in &batch[..n] {
            serve(t, flags);
        }
        crate::timer::reap(DRAIN_BATCH - n)
    };
    // A batch that was not full left the queues empty, and each later push
    // comes with an SGI of its own.
    if timers_left || n == DRAIN_BATCH && (0..cpus).any(|f| f != me && !RINGS[me][f].is_empty()) {
        gic::send_sgi(me, SGI_CMD);
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

/// The probe of the window between the section that posts a command and
/// its flush (`window-probe`; tests/init/src/smp.rs, the test of the client
/// that ends with its reply on its way).
#[cfg(feature = "window-probe")]
pub mod window {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32};

    /// The priority of the thread the probe watches: the client of the test.
    pub const LEVEL: u8 = 17;

    static OPENED: AtomicBool = AtomicBool::new(false);
    static HOLDING: AtomicBool = AtomicBool::new(false);
    static ENDED_INSIDE: AtomicBool = AtomicBool::new(false);

    /// In `flush`, before the first command WAKE to a thread at LEVEL goes
    /// into its queue once its end is held (`hold_until_replied`): waits
    /// until the CPU of the thread saw the reply (2 s at most, for a host
    /// that is busy), then 20 ms more, in which that CPU ends the thread,
    /// and says whether it did.
    pub fn open(t: NonNull<Thread>, flag: u8) {
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
    /// after its look at the request of the entry that no lock covers.
    pub const WAIT_LEVEL: u8 = 14;
    /// The priority of the receiver the probe holds between the two sections
    /// of its receive.
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

    static MOVED: AtomicU32 = AtomicU32::new(0);

    /// The head of a queue of requests left it (a receiver took it, or its
    /// sender was recalled).
    pub fn head_moved() {
        MOVED.fetch_add(1, Ordering::Release);
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
}
