// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel's scheduler (spec 8, 8.1): the rules of kcore::sched over
//! the kernel's threads, the virtual timer and the cleanup queue. Every
//! entry into the kernel ends in `resume`, the one way out: a loop on the
//! empty kernel stack that handles a pending interrupt, decides, arms the
//! timer for the deadline that decision needs, the nearer of the end of a
//! quantum and the nearest timer of a program whose level's firing is not
//! queued (spec 8, 10), writing the timer only when the deadline changes,
//! and then runs the chosen thread, does one portion of cleanup (spec 7.7)
//! or sleeps in `wfi` with interrupts masked. Idle is that loop with
//! nothing ready: no thread object, and cleanup of every level runs there,
//! the firings of timers included. Between two polls for interrupts the
//! kernel does at most one portion, and it begins one only with no
//! interrupt pending. The kernel holds a reference to every thread
//! the scheduler holds, from `start` until `exit`, a thread that waits in
//! `send` or `receive` too. The queues of channels and of accepted
//! requests change together with the states of the threads that wait in
//! them, and so does the table of thread numbers (spec 6.1, 7.8), which
//! lies here, in memory the kernel takes at boot: the code that changes
//! them runs under OBJ (`locked`, obj.rs). The scheduler itself, with its
//! ready queue, belongs to the CPU that runs it (local.rs): it takes no
//! lock, and the code under OBJ reaches it freely.

use crate::arch::{self, gic, timer};
use crate::channel::{self, Wait};
use crate::local::local;
use crate::thread::{self, THREADS, Thread};
use crate::{cleanup, syscall};
use abi::{Error, Policy};
use core::ptr::NonNull;
use kcore::sched::{Armed, Decision, Scheduler, Timer};
use kcore::time::Clock;
use kcore::token::Table;

/// The table of thread numbers (spec 6.1, 7.8): THREADS entries of 16
/// bytes.
pub type Tokens = Table<Thread, THREADS>;

pub(crate) struct Sched {
    s: Scheduler<Thread>,
    /// The deadline the timer holds.
    armed: Armed,
    /// Counter ticks spent asleep in `wfi`, for KSTATS and `uptime`
    /// (milestone 1.4).
    idle: u64,
    /// The kernel handles the interrupt that woke it from `wfi`.
    waking: bool,
    /// The deadline of the timer interrupt that came last, and whether it
    /// woke the kernel from `wfi`, until a thread runs after it or the
    /// kernel sleeps again.
    /// The deadline, never 0, and whether it woke the kernel: 0 is none,
    /// all zeros, which keeps a CPU's data in .bss (an `Option` of a pair
    /// with a `bool` would not be zeros).
    fired: (u64, bool),
    /// The longest time from a deadline to the thread run after its
    /// interrupt, in ticks: after `wfi`, and otherwise.
    idle_latency: u64,
    irq_latency: u64,
}

impl Sched {
    /// The quantum is 0 until `init` knows the counter's frequency.
    pub(crate) const fn new() -> Sched {
        Sched {
            s: Scheduler::new(0),
            armed: Armed::new(),
            idle: 0,
            waking: false,
            fired: (0, false),
            idle_latency: 0,
            irq_latency: 0,
        }
    }
}

/// Starts the timing of an entry from EL0, which the CPU keeps for itself
/// (`Local::entry`): interrupts stay masked from the exception vector
/// through the first poll, in `exit_loop` or between two portions of a long
/// call (`entry_polled`).
#[inline(always)]
pub fn entry_started() -> u64 {
    // The exception entry synchronized: no ISB before the read.
    let now = timer::now_unordered();
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    unsafe { (*local().entry.get()).0 = now };
    #[cfg(feature = "measure")]
    crate::obj::stretch_begins(now);
    now
}

/// The interval of the entry ends at its first poll for an interrupt:
/// `exit_loop`'s, or one between two portions of a long call (spec 7.7).
#[inline(always)]
pub fn entry_polled() {
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    if unsafe { (*local().entry.get()).0 } != 0 {
        let now = timer::now();
        entry_polled_at(now);
        // The next portion begins a stretch of its own (`entry_started`).
        #[cfg(feature = "measure")]
        crate::obj::stretch_ends(now);
    }
}

/// A poll of the way out of the kernel at `now`: the stretch of the entry,
/// if open, ends, and so does the stretch of OBJ's takes, and a new one
/// begins (obj::stretch_ends).
#[inline(always)]
fn polled_at(now: u64) {
    entry_polled_at(now);
    #[cfg(feature = "measure")]
    {
        crate::obj::stretch_ends(now);
        crate::obj::stretch_begins(now);
    }
}

/// `entry_polled` with the counter value `now`, which the caller read just
/// before the poll: the way out of the kernel reads it once for the poll
/// and the decision.
#[inline(always)]
fn entry_polled_at(now: u64) {
    let cpu = local();
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    let timing = unsafe { &mut *cpu.entry.get() };
    if timing.0 != 0 {
        // `now` was read after the entry's; a counter that steps back (the
        // A64's, #355) gives an interval of 0.
        let elapsed = now.saturating_sub(timing.0);
        if elapsed > timing.1 {
            timing.1 = elapsed;
        }
        timing.0 = 0;
        cpu.time.entered(elapsed);
    }
}

pub fn longest_entry_to_poll() -> u64 {
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    unsafe { (*local().entry.get()).1 }
}

/// Whether an entry started and has not polled yet.
#[cfg(feature = "ktest")]
pub fn entry_unpolled() -> bool {
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    unsafe { (*local().entry.get()).0 != 0 }
}

/// The start of the open entry interval, 0 when it has polled, and the
/// longest interval so far.
#[cfg(feature = "ktest")]
pub fn entry_timing() -> (u64, u64) {
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    unsafe { *local().entry.get() }
}

/// Puts `timing` back, as `entry_timing` read it.
#[cfg(feature = "ktest")]
pub fn set_entry_timing(timing: (u64, u64)) {
    // SAFETY: the CPU's own field, with interrupts masked, as above.
    unsafe { *local().entry.get() = timing };
}

/// The table of thread numbers, which OBJ guards: only
/// `locked` reaches it, while it holds that lock. Zeroed at boot (spec
/// 7.8).
static TOKENS: crate::obj::Guarded<Tokens> = crate::obj::Guarded::new(Table::new());

/// What the scheduler counts for KSTATS (spec 16), in counter ticks.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Asleep in `wfi`.
    pub idle: u64,
    /// The longest time from the deadline of the timer's interrupt, the end
    /// of a quantum or a timer of a program, to the thread run after it,
    /// when the interrupt woke the kernel from `wfi`.
    pub idle_latency: u64,
    /// The same for an interrupt that came while the kernel was awake: at
    /// EL0, or found by the poll on the way out.
    pub irq_latency: u64,
}

/// The scheduler's counters for KSTATS.
pub fn stats() -> Stats {
    let g = local().sched.lock();
    Stats {
        idle: g.idle,
        idle_latency: g.idle_latency,
        irq_latency: g.irq_latency,
    }
}

/// The EL1 virtual timer as the scheduler writes it.
struct VirtualTimer;

impl Timer for VirtualTimer {
    fn arm(&mut self, deadline: u64) {
        timer::arm(deadline);
    }

    fn disarm(&mut self) {
        timer::disarm();
    }
}

/// Sets the round-robin quantum, abi::RR_QUANTUM_NS, in ticks of `clock`:
/// 250 000 at QEMU's 62.5 MHz, 96 000 at the A64's 24 MHz. Runs at boot,
/// before any thread starts.
pub fn init(clock: Clock) {
    let quantum = clock.ns_to_ticks(abi::RR_QUANTUM_NS);
    QUANTUM.store(quantum, core::sync::atomic::Ordering::Relaxed);
    local().sched.lock().s.set_quantum(quantum);
}

/// The quantum in ticks, which every CPU's scheduler takes (`init_cpu`).
static QUANTUM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Sets the quantum of the scheduler of the CPU that runs this, which
/// `init` set on CPU 0.
pub fn init_cpu() {
    let quantum = QUANTUM.load(core::sync::atomic::Ordering::Relaxed);
    local().sched.lock().s.set_quantum(quantum);
    local().time.started(timer::now());
}

/// What CPU `index` counts about its time (`CpuTime::read`, with the counter
/// read after its words) and
/// the number of CPUs that are up, None for a CPU past them (object_info
/// CPU). Takes no lock: the words are the owner's, read with one load each.
pub fn cpu_time(index: usize) -> Option<(usize, [u64; 3])> {
    let cpus = crate::smp::cpus();
    (index < cpus).then(|| (cpus, arch::cpu::block(index).local.time.read(timer::now)))
}

/// A stopped thread becomes ready: the tail of its level with a new
/// quantum. The kernel takes a reference to it, which `exit` drops.
/// BAD_STATE for a thread that started before. thread::start comes here,
/// once it knows the thread's process lives.
pub fn start(t: NonNull<Thread>) -> Result<(), Error> {
    // The flag of START goes into the thread inside the section (cmd::post).
    crate::obj::assert_held();
    if !thread::mark_started(t) {
        return Err(Error::BadState);
    }
    thread::retain(t);
    if is_local(t) {
        // SAFETY: the caller holds a reference to `t`; the one taken above
        // keeps it alive, and a pool object never moves, until `exit`.
        unsafe { local().sched.lock().s.start(t) }.expect("a thread that started before");
    } else {
        crate::cmd::post(t, crate::cmd::START);
    }
    Ok(())
}

/// Whether the thread `t` runs on this CPU, which changes its scheduling
/// state (cmd.rs).
#[inline(always)]
pub fn is_local(t: NonNull<Thread>) -> bool {
    thread::cpu_of(t) == arch::cpu::this().index()
}

/// The end of a wait of `t`, which the section took out of its queue:
/// ready on its own CPU, at once when that is this one, by a command
/// otherwise (cmd::WAKE).
///
/// # Safety
/// As for `Scheduler::wake`.
#[inline(always)]
pub unsafe fn wake(k: &mut Locked<'_>, t: NonNull<Thread>) {
    if is_local(t) {
        // SAFETY: the caller's promise.
        unsafe { k.s.wake(t) };
    } else {
        crate::cmd::post(t, crate::cmd::WAKE);
    }
}

/// The thread `t`, parked and out of its process's list, continues: on its
/// CPU, by a command when that is another one (cmd::UNPARK).
///
/// # Safety
/// As for `Scheduler::unpark`.
pub unsafe fn unpark(k: &mut Locked<'_>, t: NonNull<Thread>) {
    if is_local(t) {
        // SAFETY: the caller's promise.
        unsafe { k.s.unpark(t) };
    } else {
        crate::cmd::post(t, crate::cmd::UNPARK);
    }
}

/// A boost of `t` to `level`: on its own CPU at once when that is this one,
/// by a command otherwise, which also moves its slot in the queue it waits
/// in and goes on along the chain of requests (cmd::BOOST, `serve_level`);
/// a thread of another CPU that the scheduler no longer holds is left alone.
/// True when it was done here.
///
/// # Safety
/// As for `Scheduler::boost`.
pub unsafe fn boost(k: &mut Locked<'_>, t: NonNull<Thread>, level: u8, ceiling: u8) -> bool {
    if is_local(t) {
        // SAFETY: the caller's promise.
        unsafe { k.s.boost(t, level, ceiling) };
        return true;
    }
    // The owner let the thread go (`exit`) and its end is on its way: the
    // number stays until `serve_exit`, so the chain of requests still finds
    // the thread, but a command posted now would stand in the queue past the
    // release of the kernel's reference.
    if !thread::is_held(t) {
        #[cfg(feature = "window-probe")]
        crate::cmd::window::boost_left_alone(t);
        return false;
    }
    crate::cmd::ask_boost(t, level, ceiling);
    crate::cmd::post(t, crate::cmd::BOOST);
    false
}

/// A boost of `t` to `level` with no command, for a thread that runs on this
/// CPU or waits. Another CPU may do it for a thread that waits only: its CPU
/// touches nothing of it until the end of its wait, which only a section
/// under OBJ gives (`wake`), and a waiting thread stands in no ready queue,
/// so the boost changes its level and nothing else (`Scheduler::boost`).
/// A thread that is ready or runs on another CPU takes a command
/// (`boost`). Checked in the test build.
///
/// # Safety
/// As for `Scheduler::boost`; `t` waits or runs on this CPU.
pub unsafe fn boost_in_place(k: &mut Locked<'_>, t: NonNull<Thread>, level: u8, ceiling: u8) {
    debug_assert!(
        // SAFETY: the caller's promise; only the state is read.
        is_local(t) || unsafe { t.as_ref() }.sched.state() == kcore::sched::State::Waiting,
        "a thread of another CPU is boosted with no command while it does not wait"
    );
    // SAFETY: the caller's promise.
    unsafe { k.s.boost(t, level, ceiling) };
}

/// START, served by the CPU of the thread, unless the thread ended since:
/// the kernel's reference goes with its EXIT.
pub fn serve_start(t: NonNull<Thread>) {
    crate::obj::assert_held();
    if !thread::is_held(t) {
        return;
    }
    // SAFETY: the kernel's reference, which `start` took, keeps the thread.
    unsafe { local().sched.lock().s.start(t) }.expect("a thread that started before");
}

/// UNPARK, served by the CPU of the thread, unless it ended since.
pub fn serve_unpark(t: NonNull<Thread>) {
    crate::obj::assert_held();
    if !thread::is_held(t) {
        return;
    }
    // SAFETY: as above; the portion that asked took the thread out of its
    // process's list.
    unsafe { local().sched.lock().s.unpark(t) };
}

/// WAKE, served by the CPU of the thread, unless it ended since, once the
/// copy of its message is made (cmd::drain waits for it).
pub fn serve_wake(t: NonNull<Thread>) {
    crate::obj::assert_held();
    if !thread::is_held(t) {
        return;
    }
    // SAFETY: as above; the section that asked took the thread out of its
    // queue.
    unsafe { local().sched.lock().s.wake(t) };
}

/// LEVEL and BOOST, served by the CPU of the thread, under OBJ: the new
/// level, then the boost, then the slot of a thread that waits follows its
/// level in its queue (`channel::requeue`), and the rise goes on along the
/// chain of requests.
pub fn serve_level(t: NonNull<Thread>) {
    crate::obj::assert_held();
    // What was asked goes whether or not the thread ended meanwhile: its
    // number is another thread's next, once it gives it back (EXIT).
    let (level, boost) = crate::cmd::take_level(t);
    if !thread::is_held(t) {
        return;
    }
    let now = timer::now();
    let waits = locked(|k| {
        // SAFETY: as above; the scheduler's threads are alive.
        unsafe {
            if level != 0 {
                let (priority, policy, tail) = unpack_level(level);
                let _ = k.s.set_priority(t, priority, policy, tail, now);
            }
            if boost != 0 {
                k.s.boost(t, (boost & 0x3f) as u8, ((boost >> 6) & 0x3f) as u8);
            }
            channel::requeue(t, k)
        }
    });
    if let Some(w) = waits {
        // SAFETY: the thread still waits in `w`.
        unsafe { channel::raise(w) };
    }
}

/// EXIT, served by the CPU of the thread: it leaves the scheduler, its
/// registers stop being the CPU's live ones, and the kernel's reference
/// goes when the asker left it to this CPU.
pub fn serve_exit(t: NonNull<Thread>) {
    crate::obj::assert_held();
    // The cause, a priority, in bits 0-7; bit 8 hands the reference over.
    let ask = crate::cmd::take_exit(t);
    // SAFETY: as above.
    unsafe { local().sched.lock().s.exit(t, timer::now()) };
    if thread::current() == Some(t) {
        arch::user::clear_current();
    }
    locked(|k| {
        // SAFETY: the thread is alive; its number goes back with its end.
        unsafe { thread::give_number(t, k.tokens) }
    });
    if ask & 0x100 != 0 {
        // SAFETY: the reference is the one `start` took, which the ask
        // handed to this CPU.
        unsafe { thread::release(t, (ask & 0xff) as u8) };
    }
}

/// The word of `thread_set_priority`'s ask: the priority, the policy and
/// the tail, with a bit that says there is one.
fn pack_level(priority: u8, policy: Policy, tail: bool) -> u16 {
    1 << 15
        | u16::from(tail) << 9
        | u16::from(policy == Policy::RoundRobin) << 8
        | u16::from(priority)
}

fn unpack_level(word: u16) -> (u8, Policy, bool) {
    (
        (word & 0xff) as u8,
        if word & 0x100 != 0 {
            Policy::RoundRobin
        } else {
            Policy::Fifo
        },
        word & 0x200 != 0,
    )
}

/// Ends `t` for the scheduler, whatever its state: it never runs again,
/// its number goes back to the table (thread::give_number), and the
/// reference the kernel took at `start` goes, with `cause` for the cleanup
/// its last reference starts. A thread that waits in `send` or `receive`,
/// or for a reply, first leaves the queue its slot stands in
/// (channel::cancel), and the reference of its wait goes too (spec 6.8,
/// 7.7). When `t` was the running thread, `resume` decides who runs next.
/// A thread that ended before stays as it is. O(1).
///
/// # Safety
/// `t` is alive. When the kernel's reference is its last, `t` is queued
/// for cleanup here, and the caller does not use it afterwards.
pub unsafe fn exit(t: NonNull<Thread>, cause: u8) {
    // A thread that started runs on its CPU, which ends it (cmd::EXIT); one
    // that never started stands in no scheduler. The CPU's own end of a
    // thread with commands on their way leaves the kernel's reference and
    // the number to the command EXIT, which follows them (`serve_exit`).
    let started = thread::is_started(t);
    let remote = started && !is_local(t);
    let (held, waited) = locked(|k| {
        let deferred = remote || (started && crate::cmd::pending(t));
        // SAFETY: `t` is alive; the list of a process's parked threads is
        // under OBJ.
        if unsafe { t.as_ref() }.sched.is_parked_listed() {
            // SAFETY: a parked thread belongs to its process list.
            unsafe { crate::process::unlist_parked(t, k) };
        }
        // SAFETY: `t` and the scheduler's threads are alive; the queue
        // gives up the thread before the scheduler ends it.
        let waited = unsafe { channel::cancel(t, k) };
        if !remote {
            // SAFETY: as above.
            unsafe { k.s.exit(t, timer::now()) };
        }
        if deferred {
            // The number goes back once the owner ended the thread
            // (`serve_exit`): the arguments of its commands lie under it.
            crate::cmd::ask_exit(t, thread::mark_ended(t), cause);
            crate::cmd::post(t, crate::cmd::EXIT);
            return (false, waited);
        }
        // SAFETY: as above.
        unsafe { thread::give_number(t, k.tokens) };
        (thread::mark_ended(t), waited)
    });
    if let Some(via) = waited {
        // SAFETY: the reference was the wait's.
        unsafe { via.let_go(cause) };
    }
    if thread::current() == Some(t) {
        arch::user::clear_current();
    }
    if held {
        // SAFETY: the reference `start` took ends with the thread.
        unsafe { thread::release(t, cause) };
    }
}

/// The thread on the CPU: the one whose call or fault the kernel serves
/// now; None while the kernel runs a portion of cleanup or idles.
pub fn running() -> Option<NonNull<Thread>> {
    local().sched.lock().s.running()
}

/// Interrupt only an existing send or receive. The thread remains alive,
/// retaining its number and message buffer. No interrupt is queued for a
/// future call. A thread that waits for the reply to an accepted request
/// is not interrupted: BAD_STATE, as for a thread that waits for nothing,
/// and the reply comes once (spec 6.1). Wait references and moved handles
/// are released outside OBJ. O(1), at most four handles.
///
/// # Safety
/// `t` is alive and the caller holds a reference throughout this call.
pub unsafe fn interrupt(t: NonNull<Thread>, cause: u8) -> Result<(), Error> {
    // SAFETY: as the caller promises.
    unsafe {
        interrupt_if(t, cause, |thread| match thread.waits {
            Some(Wait::Receive(_) | Wait::Send(_)) => Ok(true),
            Some(Wait::Reply(_)) | None => Err(Error::BadState),
        })
    }
}

/// thread_upcall_request: the look at the target's state, the request
/// and the look at its wait happen under OBJ with the
/// interruption they decide, so no other path can start or end the wait
/// in between (spec 8.1). BAD_STATE for a stopped or ended thread. A
/// request that enables an entry ends a send or receive as `interrupt`
/// does; otherwise, and for a thread that waits for a reply, it stays
/// pending, and the entry comes on the thread's next way to EL0, after the
/// reply.
///
/// # Safety
/// As for `interrupt`.
pub unsafe fn request_upcall(t: NonNull<Thread>, cause: u8) -> Result<(), Error> {
    // SAFETY: as the caller promises.
    unsafe {
        interrupt_if(t, cause, |thread| {
            if !thread.is_held() {
                return Err(Error::BadState);
            }
            Ok(thread.upcall.request()?
                && matches!(thread.waits, Some(Wait::Receive(_) | Wait::Send(_))))
        })
    }?;
    if !is_local(t) {
        // The thread may be at EL0 on its CPU: that CPU enters the kernel
        // and the way back to EL0 finds the request (thread::run).
        crate::cmd::kick(thread::cpu_of(t));
    }
    Ok(())
}

/// Under the lock, `decide` says whether to end the send or receive of
/// `t`; then the interruption runs in the same critical section.
///
/// # Safety
/// As for `interrupt`.
unsafe fn interrupt_if(
    t: NonNull<Thread>,
    cause: u8,
    decide: impl FnOnce(&mut Thread) -> Result<bool, Error>,
) -> Result<(), Error> {
    let waited = locked(|k| {
        // SAFETY: the caller holds the thread; waits and queue membership
        // change together under this lock. A live IPC waiter is blocked.
        unsafe {
            if !decide(&mut *t.as_ptr())? {
                return Ok(None);
            }
            // `decide` lets only a send or a receive through: the wait
            // for a reply is never taken back (spec 6.1).
            debug_assert!(matches!(
                t.as_ref().waits,
                Some(Wait::Receive(_) | Wait::Send(_))
            ));
            let waited = channel::withdraw(t, k);
            #[cfg(feature = "window-probe")]
            crate::cmd::window::head_moved();
            syscall::set_result(t, Err(Error::Interrupted));
            wake(k, t);
            Ok::<_, Error>(Some(waited))
        }
    })?;
    let Some(waited) = waited else {
        return Ok(());
    };
    // SAFETY: queued send handles are still owned by the interrupted thread.
    unsafe { thread::drop_transit(t, cause) };
    if let Some(via) = waited {
        // SAFETY: withdraw removed the wait that held this reference.
        unsafe { via.let_go(cause) };
    }
    Ok(())
}

/// yield: the running thread goes to the tail of its level with a new
/// quantum; `resume` runs the next thread of that level, or the same one
/// when it is alone there. Lower levels never run through yield.
pub fn yield_running() {
    // SAFETY: the scheduler's threads are alive (`start`).
    unsafe { local().sched.lock().s.yield_running(timer::now()) };
}

/// thread_set_priority: `priority` (1-63) becomes the base priority of
/// `t`, and the effective one follows unless a boost keeps it higher (spec
/// 6.6); the thread moves by the rules of `pthread_setschedprio`
/// (kcore::sched), and the slot of one that waits moves in its queue by
/// the same rules (spec 6.1, 6.3; channel::requeue); then, after the lock,
/// a channel at its stage Close or a process at its stage Replies that it
/// waits in follows its top waiter (channel::raise, spec 7.7). The next
/// `resume` runs a thread raised above the running one, or another one
/// when the running thread lowered itself below it. BAD_STATE for a
/// thread that ended.
pub fn set_priority(
    t: NonNull<Thread>,
    priority: u8,
    policy: Policy,
    tail: bool,
) -> Result<(), Error> {
    let now = timer::now();
    if thread::is_started(t) && !is_local(t) {
        // The CPU of the thread applies it, moves the slot of a thread that
        // waits and goes on along the chain of requests (`serve_level`).
        // A thread that ended is BAD_STATE, as for a local one.
        return locked(|_| {
            if !thread::is_held(t) {
                return Err(Error::BadState);
            }
            crate::cmd::ask_level(t, pack_level(priority, policy, tail));
            crate::cmd::post(t, crate::cmd::LEVEL);
            Ok(())
        });
    }
    let waits = locked(|k| {
        // SAFETY: the caller holds a reference to `t`; the scheduler's
        // threads are alive, and so is the channel a thread waits in.
        unsafe {
            k.s.set_priority(t, priority, policy, tail, now)?;
            Ok::<_, Error>(channel::requeue(t, k))
        }
    })?;
    if let Some(w) = waits {
        // SAFETY: the thread still waits in `w`.
        unsafe { channel::raise(w) };
    }
    Ok(())
}

/// What OBJ guards for the rest of the kernel: the
/// scheduler, and the table of thread numbers.
pub struct Locked<'a> {
    pub s: &'a mut Scheduler<Thread>,
    pub tokens: &'a mut Tokens,
}

/// Runs `f` under OBJ. The queues of channels and of
/// accepted requests hold the slots of threads that wait
/// (kcore::notify::Queue), and requests take tokens from the table of
/// thread numbers, so the code that changes them, with the threads'
/// states, runs here.
pub fn locked<R>(f: impl FnOnce(&mut Locked<'_>) -> R) -> R {
    crate::obj::assert_held();
    let mut g = local().sched.lock();
    let mut tokens = TOKENS.lock();
    f(&mut Locked {
        s: &mut g.s,
        tokens: &mut tokens,
    })
}

/// The fast path of send (spec 6.4): `meet` runs under OBJ,
/// as under `locked`, given the counter value `hand_off` read before the
/// lock (the sender's stint ends and the receiver's begins at it), and
/// either makes the meeting and returns the receiver, or returns None and
/// changes nothing. The receiver then runs at once in place of the caller,
/// which waits (Scheduler::hand_off), with a new quantum from now, and the
/// timer is armed for the deadline it needs: the nearer of the end of that
/// quantum when the receiver is round robin and `next_timer`, the nearest
/// timer of a program (timer::first), which the caller read before the lock
/// (spec 8, 10). The state is the one `wake` and the next decision would
/// leave; the caller runs the receiver (thread::run). O(1).
pub fn hand_off(
    next_timer: Option<u64>,
    meet: impl FnOnce(&mut Locked<'_>, u64) -> Option<NonNull<Thread>>,
) -> Option<NonNull<Thread>> {
    let now = timer::now();
    crate::obj::assert_held();
    let mut g = local().sched.lock();
    let g = &mut *g;
    // The decision that ran the caller took the deadline that fired, and
    // no interrupt came since: its latency needs no more.
    #[cfg(feature = "ktest")]
    assert!(g.fired.0 == 0, "a fired deadline waits at the fast path");
    let mut tokens = TOKENS.lock();
    let r = meet(
        &mut Locked {
            s: &mut g.s,
            tokens: &mut tokens,
        },
        now,
    )?;
    // SAFETY: the receiver is alive, and `meet` made it the meeting's: it
    // waits in no queue, above every ready thread and the cleanup.
    unsafe { g.s.hand_off(r, now) };
    let deadline = g.s.deadline(next_timer);
    g.armed.set(&mut VirtualTimer, deadline);
    Some(r)
}

/// The timer's interrupt, before its EOI: the timer goes off, since its
/// line is level-triggered and must be quiet by the EOI, and a round-robin
/// thread whose quantum is over goes to the tail of its level; an
/// interrupt that came for a timer of a program ends no quantum. Then each
/// level of timers of programs whose top expired queues its firing in the
/// cleanup queue at that level, after OBJ (spec 10).
/// `resume` arms the timer again. The deadline that fired, CNTV_CVAL_EL0,
/// waits for the next thread to run, which measures the latency for
/// KSTATS.
pub fn timer_fired() {
    let now = timer::now();
    {
        let mut g = local().sched.lock();
        let g = &mut *g;
        g.fired = (timer::cval().max(1), g.waking);
        // The line must drop before the EOI whatever `armed` remembers: the
        // hardware said the timer is on.
        VirtualTimer.disarm();
        g.armed = Armed::new();
        // SAFETY: the scheduler's threads are alive.
        unsafe { g.s.tick(now) };
    }
    crate::timer::expire(now);
}

/// The way out of the kernel (spec 8.1, 7.7): `exit_loop` on the empty
/// kernel stack, so that neither a portion of cleanup nor the idle wait
/// depends on how deep the caller was. The caller's stack holds nothing
/// with a `Drop`: it is abandoned.
pub fn resume() -> ! {
    crate::obj::end_test_scope();
    // The copy of a message and the commands of the call go out here: every
    // exit of the kernel passes this point, a call that never returns
    // (thread_exit, process_exit, the end of a process by a fault) included.
    crate::thread::flush_copy();
    arch::on_empty_stack(exit_loop)
}

/// `resume` for a call that holds a section: the section ends here, before
/// the stack is abandoned.
pub fn resume_from(section: crate::obj::Section) -> ! {
    drop(section);
    resume()
}

/// The loop every way out of the kernel takes: an interrupt that is
/// pending is acknowledged and handled first; then the decision, and the
/// chosen thread runs at EL0, one portion of cleanup runs, or the kernel
/// sleeps until an interrupt. A portion begins only with no interrupt
/// pending. TTBR0, TPIDR_EL1 and the FP registers keep
/// the last thread's meanwhile, so going back to that thread costs
/// nothing; the idle wait takes TTBR0 off it (`aspace::leave`). Leaves only through thread::run.
extern "C" fn exit_loop() -> ! {
    loop {
        let mut now = timer::now();
        polled_at(now);
        if arch::irq_pending()
            && let Some(ack) = gic::acknowledge()
        {
            crate::interrupt::handle(ack);
            // The commands the interrupt posted go out before the decision.
            crate::cmd::flush_posted();
            now = timer::now();
        }
        match decide(now) {
            Some(Decision::Run(t)) => {
                // The kernel stack is empty and a way to EL0 follows: a
                // quiescent point for the objects other CPUs retire, and the
                // end of a wait for every CPU to be in the kernel once (qsbr).
                if crate::qsbr::pending() {
                    crate::qsbr::quiesce();
                }
                thread::run(t)
            }
            // Another line of the same priority shows only after the EOI
            // of the one just handled (GICv2 running priority): poll again
            // first. Deciding again costs nothing: the running thread went
            // to the head of its level already.
            Some(Decision::Clean) if arch::irq_pending() => {}
            Some(Decision::Clean) => {
                cleanup::portion();
                crate::cmd::flush_posted();
                // The kernel stack is empty again: a quiescent point, where
                // what the portion retired may go (qsbr). The way to EL0 is
                // one too, for the objects another CPU retires (stage 4).
                if crate::qsbr::pending() {
                    crate::qsbr::quiesce();
                }
            }
            Some(Decision::Idle) => sleep(),
            None => {}
        }
    }
}

/// Decides what the kernel does from now on and arms the timer for the
/// deadline that needs: the nearer of the end of a round-robin thread's
/// quantum and the nearest timer of a program (timer::first); only the
/// timer for a FIFO thread, for cleanup or while idle (spec 8, 10). The
/// lock of the timers goes before the scheduler's is taken. A thread chosen
/// after a timer's interrupt ends that interrupt's latency. `now` is the
/// counter as `exit_loop` read it before the poll for an interrupt, or after
/// the one it handled.
fn decide(now: u64) -> Option<Decision<Thread>> {
    #[cfg(feature = "locked-decide")]
    let cleanup = cleanup::top();
    #[cfg(not(feature = "locked-decide"))]
    let cleanup = cleanup::top_for_decide();
    #[cfg(feature = "locked-decide")]
    let next_timer = crate::timer::first();
    #[cfg(not(feature = "locked-decide"))]
    let next_timer = crate::timer::first_for_decide();
    let mut g = local().sched.lock();
    let g = &mut *g;
    // SAFETY: the scheduler's threads are alive.
    let decision = unsafe { g.s.pick(now, cleanup) };
    if let Decision::Run(t) = decision
        && crate::process::gated_thread(t)
    {
        // A gated process parks its thread: the parked list is a link.
        crate::obj::serving(crate::obj::ENTRY_PARK);
        let _obj = crate::obj::lock();
        let mut tokens = TOKENS.lock();
        let mut k = Locked {
            s: &mut g.s,
            tokens: &mut tokens,
        };
        if crate::process::park_selected(t, &mut k) {
            return None;
        }
    }
    if let Decision::Run(_) = decision
        && g.fired.0 != 0
    {
        let (deadline, woke) = core::mem::take(&mut g.fired);
        let latency = now.saturating_sub(deadline);
        let max = if woke {
            &mut g.idle_latency
        } else {
            &mut g.irq_latency
        };
        *max = (*max).max(latency);
    }
    if let Decision::Idle = decision {
        // Nothing runs after the interrupt: the sleep that follows is no
        // part of its latency.
        g.fired = (0, false);
    }
    let deadline = g.s.deadline(next_timer);
    g.armed.set(&mut VirtualTimer, deadline);
    Some(decision)
}

/// Nothing to do: sleeps in `wfi` with interrupts masked until one is
/// pending, and handles it; the time asleep counts for KSTATS.
fn sleep() {
    crate::mm::aspace::leave();
    crate::testpoint::idle();
    let slept = timer::now();
    #[cfg(feature = "measure")]
    crate::obj::stretch_ends(slept);
    local().time.sleeps(slept);
    crate::qsbr::idle();
    let ack = gic::wait();
    crate::qsbr::awake();
    let woke = timer::now();
    #[cfg(feature = "measure")]
    crate::obj::stretch_begins(woke);
    local().time.woke(woke);
    {
        let mut g = local().sched.lock();
        g.idle += woke.saturating_sub(slept);
        g.waking = true;
    }
    if let Some(ack) = ack {
        crate::interrupt::handle(ack);
        crate::cmd::flush_posted();
    }
    local().sched.lock().waking = false;
}

/// The ready thread that runs next at `level`.
#[cfg(feature = "ktest")]
pub fn first(level: u8) -> Option<NonNull<Thread>> {
    local().sched.lock().s.ready().first(level)
}

/// What the scheduler holds now (test builds).
#[cfg(feature = "ktest")]
pub struct View {
    /// The running thread, and the first ready thread of the top level.
    pub running: Option<NonNull<Thread>>,
    pub ready: Option<NonNull<Thread>>,
    /// The deadline the scheduler needs with no timer of a program: the end
    /// of the running thread's quantum when it is round robin.
    pub slice_end: Option<u64>,
    /// The deadline the timer holds.
    pub armed: Option<u64>,
}

/// The scheduler's `View` now (test builds).
#[cfg(feature = "ktest")]
pub fn view() -> View {
    let g = local().sched.lock();
    View {
        running: g.s.running(),
        ready: g.s.ready().top().and_then(|l| g.s.ready().first(l)),
        slice_end: g.s.deadline(None),
        armed: g.armed.get(),
    }
}

/// Forgets the longest latencies, so that a test measures its own.
#[cfg(feature = "ktest")]
pub fn reset_latencies() {
    let mut g = local().sched.lock();
    g.idle_latency = 0;
    g.irq_latency = 0;
}
