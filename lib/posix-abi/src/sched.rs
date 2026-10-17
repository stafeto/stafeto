// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Scheduling of processes and threads (XSH 2.8.4, 2.9.4; spec 2, 3.5),
//! the priorities of mutexes, and the lending of a level to the holder of a
//! mutex.
//!
//! SCHED_OTHER and SCHED_RR are the kernel's round-robin policy and
//! SCHED_FIFO its FIFO policy. A priority of the last two runs from 1 to 32;
//! SCHED_OTHER has only 0. The top level of the application threads of a
//! process is the level its main thread starts at (the layer keeps the level
//! above it); priority 32 stands there, and priority p below it, down to
//! level 1: the level of priority p is `top - 32 + p`, at least 1 and at
//! most the top. A process whose top is above 32 has SCHED_OTHER at `top - 32`,
//! below priority 1: a thread of a real-time policy runs before the threads
//! that have none, and the main thread moves there when the process starts.
//! With a top of 32 or less SCHED_OTHER stays at the top, the base level.
//!
//! A thread's POSIX policy and priority are in its block (`sched`); its
//! base level follows from them (`base_level`). The level it runs at is the
//! highest of its base level, the level its waiters lend it and the ceiling
//! of the PTHREAD_PRIO_PROTECT mutexes it holds (`effective_level`); a
//! thread in a section of the layer stays at the ceiling of the process
//! meanwhile, and its section's end sets the level again.
//!
//! Lending (PTHREAD_PRIO_INHERIT): a thread that waits for a mutex enters
//! its level in its own block (`pi_level`), with the number of the holder
//! (`pi_owner`); the holder's `inherited` level is the highest of those of
//! the threads that wait for it. A holder that waits for another mutex lends
//! on, to a depth of 8; a cycle of holders is EDEADLK. One lock serializes
//! the changes. A holder that unlocks takes its waiters' levels off itself
//! before it wakes them, so that the highest of them runs at once. Every
//! change of a level is one `thread_set_priority`.

use crate::constants::*;
use core::sync::atomic::{AtomicU32, Ordering};
use posix_sync::{LayerLock, Woken};
use posix_thread::{Block, effective_level, flag};
use rt::abi::Policy;
use rt::handle::{Handle, Thread};
use rt::sys;

pub const SCHED_OTHER: i32 = 0;
pub const SCHED_FIFO: i32 = 1;
pub const SCHED_RR: i32 = 2;
/// The least and the greatest priority of SCHED_FIFO and SCHED_RR.
pub const MIN_PRIORITY: i32 = 1;
pub const MAX_PRIORITY: i32 = 32;
/// How far the lending goes along a chain of holders that wait.
const CHAIN_DEPTH: usize = 8;

/// The level of the main thread when it started: the top of the levels of
/// the application threads of the process.
static TOP: AtomicU32 = AtomicU32::new(0);

/// The main thread's level, once it is attached (`attach_resources`).
pub(crate) fn set_top(level: u8) {
    TOP.store(u32::from(level), Ordering::Relaxed);
}

fn top() -> Result<u8, i32> {
    match TOP.load(Ordering::Relaxed) {
        0 => Err(EIO),
        level => Ok(level as u8),
    }
}

/// The word of `sched` for `policy` and `priority`.
pub(crate) fn pack(policy: i32, priority: i32) -> u64 {
    policy as u64 & 0xFF | (priority as u64 & 0xFF) << 8
}

/// The policy and priority in a word of `sched`.
pub(crate) fn unpack(word: u64) -> (i32, i32) {
    ((word & 0xFF) as i32, (word >> 8 & 0xFF) as i32)
}

/// sched_get_priority_min and sched_get_priority_max: EINVAL for another
/// policy.
pub fn priority_range(policy: i32, max: bool) -> Result<i32, i32> {
    match policy {
        SCHED_OTHER => Ok(0),
        SCHED_FIFO | SCHED_RR => Ok(if max { MAX_PRIORITY } else { MIN_PRIORITY }),
        _ => Err(EINVAL),
    }
}

/// The kernel policy of a POSIX policy.
fn kernel_policy(policy: i32) -> Policy {
    if policy == SCHED_FIFO {
        Policy::Fifo
    } else {
        Policy::RoundRobin
    }
}

/// The level of SCHED_OTHER under a process whose top level is `top`.
fn other_level(top: u8) -> u8 {
    // With room under the top for 32 levels of priorities, SCHED_OTHER is
    // below them; a process with less room keeps it at the top.
    if i32::from(top) > MAX_PRIORITY {
        top - MAX_PRIORITY as u8
    } else {
        top
    }
}

/// The base level and the kernel policy of `policy` and `priority`: EINVAL
/// for a policy or priority out of range.
pub(crate) fn level_of(policy: i32, priority: i32) -> Result<(u8, Policy), i32> {
    let top = top()?;
    match policy {
        SCHED_OTHER if priority == 0 => Ok((other_level(top), Policy::RoundRobin)),
        SCHED_FIFO | SCHED_RR if (MIN_PRIORITY..=MAX_PRIORITY).contains(&priority) => {
            // At least one above SCHED_OTHER, at most the top.
            let level = (i32::from(top) - MAX_PRIORITY + priority).max(1) as u8;
            Ok((level, kernel_policy(policy)))
        }
        _ => Err(EINVAL),
    }
}

/// The scheduling the next thread of the calling thread starts with (an
/// attribute object with PTHREAD_EXPLICIT_SCHED): checked here, so that
/// pthread_create can say EINVAL; a negative policy forgets it.
pub fn next_sched(policy: i32, priority: i32) -> Result<(), i32> {
    let block = crate::threads::own_block();
    if policy < 0 {
        block.next_sched.store(0, Ordering::Relaxed);
        return Ok(());
    }
    level_of(policy, priority)?;
    if !permitted(
        unpack(block.sched.load(Ordering::Relaxed)),
        (policy, priority),
    ) {
        return Err(EPERM);
    }
    block
        .next_sched
        .store(1 << 63 | pack(policy, priority), Ordering::Relaxed);
    Ok(())
}

/// The scheduling the thread being made takes: the creator's `sched`, or
/// what `next_sched` set once. Returns the word, the base level and the
/// kernel policy.
pub(crate) fn for_new_thread(creator: &Block) -> Result<(u64, u8, Policy), i32> {
    let next = creator.next_sched.swap(0, Ordering::Relaxed);
    if next >> 63 != 0 {
        let (policy, priority) = unpack(next);
        let (level, kernel) = level_of(policy, priority)?;
        return Ok((pack(policy, priority), level, kernel));
    }
    let base = creator.base_level.load(Ordering::Relaxed) as u8;
    let kernel =
        Policy::from_raw(creator.policy.load(Ordering::Relaxed)).unwrap_or(Policy::RoundRobin);
    Ok((creator.sched.load(Ordering::Relaxed), base, kernel))
}

/// Sets the level of the thread of `block` to the level it ought to run at
/// (its effective level), unless it is in a section of the layer, whose end
/// sets it. `tail` puts the thread at the tail of the new level.
fn apply(block: &Block, native: &Handle<Thread>, tail: bool) {
    if block.flags.load(Ordering::SeqCst) & (flag::BUCKET | flag::RAISED_MASK) != 0 {
        return;
    }
    let level = effective_level(block);
    let policy =
        Policy::from_raw(block.policy.load(Ordering::Relaxed)).unwrap_or(Policy::RoundRobin);
    let _ = if tail {
        sys::thread_set_priority_tail(native, level, policy)
    } else {
        sys::thread_set_priority(native, level, policy)
    };
}

/// pthread_setschedparam and sched_setscheduler (`tail`), pthread_setschedprio
/// and sched_setparam: the policy (negative: the thread's) and priority of
/// the thread `id`. The thread goes to the tail of its level (`tail`) or by
/// the rules of pthread_setschedprio. Returns the old policy.
pub fn thread_set(id: u64, policy: i32, priority: i32, tail: bool) -> Result<i32, i32> {
    let own = crate::threads::thread_number() == id;
    crate::relibc::with_target(id, |block, native| {
        let (old_policy, _) = unpack(block.sched.load(Ordering::Relaxed));
        let policy = if policy < 0 { old_policy } else { policy };
        let (level, kernel) = level_of(policy, priority)?;
        if !permitted(
            unpack(block.sched.load(Ordering::Relaxed)),
            (policy, priority),
        ) {
            return Err(EPERM);
        }
        block.sched.store(pack(policy, priority), Ordering::Relaxed);
        block.policy.store(kernel as u64, Ordering::Relaxed);
        if own {
            // A thread that moves itself swaps its channel and its timer for
            // ones at the new level, as set_level does.
            crate::threads::move_to(level, kernel, tail)?;
        } else {
            block.base_level.store(u32::from(level), Ordering::Relaxed);
            apply(block, native, tail);
        }
        Ok(old_policy)
    })?
}

/// The level a new process image starts at and the scheduling word its
/// main thread applies to itself: the top level of the caller and `spec`
/// (policy and priority), or the caller's own scheduling for None. EINVAL
/// for a policy or priority out of range, EPERM for a rise the caller may
/// not make.
pub(crate) fn for_child(spec: Option<(i32, i32)>) -> Result<(u8, u64), i32> {
    let own = unpack(crate::threads::own_block().sched.load(Ordering::Relaxed));
    let (policy, priority) = spec.unwrap_or(own);
    level_of(policy, priority)?;
    if spec.is_some() && !permitted(own, (policy, priority)) {
        return Err(EPERM);
    }
    Ok((top()?, START | pack(policy, priority)))
}

/// The POSIX policy of the calling thread.
pub fn own_policy() -> i32 {
    unpack(crate::threads::own_block().sched.load(Ordering::Relaxed)).0
}

/// Bit 63 of a start word: the word names a scheduling.
pub(crate) const START: u64 = 1 << 63;

/// The main thread of a new image applies the scheduling its parent chose
/// (`Page::start_sched`): the checks were the parent's.
pub(crate) fn start_apply(word: u64) {
    // A process that nobody gave a scheduling starts as SCHED_OTHER, below
    // the real-time priorities.
    let word = if word & START == 0 {
        START | pack(SCHED_OTHER, 0)
    } else {
        word
    };
    let (policy, priority) = unpack(word);
    let Ok((level, kernel)) = level_of(policy, priority) else {
        return;
    };
    let block = crate::threads::own_block();
    block.sched.store(pack(policy, priority), Ordering::Relaxed);
    block.policy.store(kernel as u64, Ordering::Relaxed);
    if level != block.base_level.load(Ordering::Relaxed) as u8 || kernel != Policy::RoundRobin {
        let _ = crate::threads::move_to(level, kernel, false);
    }
}

/// pthread_getschedparam: the policy and priority of the thread `id`.
pub fn thread_get(id: u64) -> Result<(i32, i32), i32> {
    crate::relibc::with_target(id, |block, _| unpack(block.sched.load(Ordering::Relaxed)))
}

/// Which thread a process ID names for the scheduling calls of POSIX: the
/// caller's own thread for 0 (as Linux has it) and the main thread for the
/// caller's PID. The process of another PID is checked to exist; its
/// scheduling is not the caller's to read or set (EPERM).
fn thread_of(pid: i32) -> Result<u64, i32> {
    if pid < 0 {
        return Err(ESRCH);
    }
    if pid == 0 {
        return Ok(crate::threads::thread_number());
    }
    if pid == crate::process::getpid() {
        return Ok(1);
    }
    // A process that does not exist is ESRCH whoever asks; one that does
    // is not the caller's to read or set (EPERM). The system process
    // (PID 1, the process service) exists and is the system's.
    if pid == proto_process::INIT_PID as i32 {
        return Err(EPERM);
    }
    match crate::process::kill(pid, 0) {
        Ok(()) | Err(EPERM) => Err(EPERM),
        Err(e) => Err(e),
    }
}

/// Whether a caller may change a thread from `old` to `new` (policy,
/// priority): a user other than root moves neither into a real-time policy
/// from SCHED_OTHER nor to a higher priority of one (EPERM, as the limit of
/// real-time priority of Linux does at its default). Who the user is costs a
/// request to the process service, which only a rise asks.
fn permitted(old: (i32, i32), new: (i32, i32)) -> bool {
    let rises = new.0 != SCHED_OTHER && (old.0 == SCHED_OTHER || new.1 > old.1);
    !rises || crate::process::geteuid() == 0
}

/// sched_getscheduler.
pub fn getscheduler(pid: i32) -> Result<i32, i32> {
    thread_get(thread_of(pid)?).map(|(policy, _)| policy)
}

/// sched_getparam.
pub fn getparam(pid: i32) -> Result<i32, i32> {
    thread_get(thread_of(pid)?).map(|(_, priority)| priority)
}

/// sched_setscheduler (a policy) and sched_setparam (a negative policy):
/// the old policy.
pub fn set(pid: i32, policy: i32, priority: i32) -> Result<i32, i32> {
    thread_set(thread_of(pid)?, policy, priority, true)
}

// ---- PTHREAD_PRIO_PROTECT ----

/// The caller takes a mutex of ceiling `priority` (POSIX, 1 to 32): it runs
/// at least at that priority's level until `protect_leave`. EINVAL for a
/// priority out of range or a caller with a higher priority than the
/// ceiling; EAGAIN when it holds eight such mutexes.
pub fn protect_enter(priority: i32) -> Result<(), i32> {
    let block = crate::threads::own_block();
    let (policy, own) = unpack(block.sched.load(Ordering::Relaxed));
    if policy != SCHED_OTHER && own > priority {
        return Err(EINVAL);
    }
    let (level, _) = level_of(SCHED_FIFO, priority)?;
    let mut bytes = block.protect.load(Ordering::Relaxed).to_le_bytes();
    let Some(free) = bytes.iter_mut().find(|b| **b == 0) else {
        return Err(EAGAIN);
    };
    *free = level;
    block
        .protect
        .store(u64::from_le_bytes(bytes), Ordering::SeqCst);
    crate::relibc::with_target(crate::threads::thread_number(), |block, native| {
        apply(block, native, false)
    })
}

/// The caller let go of a mutex of ceiling `priority`.
pub fn protect_leave(priority: i32) {
    let block = crate::threads::own_block();
    let Ok((level, _)) = level_of(SCHED_FIFO, priority) else {
        return;
    };
    let mut bytes = block.protect.load(Ordering::Relaxed).to_le_bytes();
    if let Some(slot) = bytes.iter_mut().find(|b| **b == level) {
        *slot = 0;
    }
    block
        .protect
        .store(u64::from_le_bytes(bytes), Ordering::SeqCst);
    let _ = crate::relibc::with_target(crate::threads::thread_number(), |block, native| {
        apply(block, native, false)
    });
}

// ---- PTHREAD_PRIO_INHERIT ----

static PI_LOCK: LayerLock = LayerLock::raising();

/// Works out again what the waiters lend the holder `start`, and on along
/// the chain of holders that wait: EDEADLK when the chain comes back to a
/// thread on it (`own` first).
fn propagate(own: u64, start: u64) -> Result<(), i32> {
    let mut seen = [0u64; CHAIN_DEPTH + 1];
    seen[0] = own;
    let mut id = start;
    for depth in 1..=CHAIN_DEPTH {
        if seen[..depth].contains(&id) {
            return Err(EDEADLK);
        }
        seen[depth] = id;
        let next = crate::relibc::with_target(id, |block, native| {
            let mut level = 0;
            crate::relibc::each_live(|index, _, waiter| {
                if u64::from(waiter.pi_owner.load(Ordering::SeqCst)) == id && index as u64 + 1 != id
                {
                    level = level.max(waiter.pi_level.load(Ordering::SeqCst));
                }
            });
            if block.inherited.swap(level, Ordering::SeqCst) != level {
                apply(block, native, false);
            }
            // This thread waits for a mutex too: the level it lends on is
            // its own, which the lending raised.
            let owner = block.pi_owner.load(Ordering::SeqCst);
            if owner != 0 {
                block
                    .pi_level
                    .store(u32::from(effective_level(block)), Ordering::SeqCst);
            }
            u64::from(owner)
        });
        match next {
            Ok(0) | Err(_) => return Ok(()),
            Ok(owner) => id = owner,
        }
    }
    Ok(())
}

/// futex_wait for a mutex of PTHREAD_PRIO_INHERIT that the thread `owner`
/// holds: as `posix_sync::futex_wait`, with the waiter's level lent to the
/// owner while it waits. EDEADLK for a cycle.
pub fn futex_wait_pi(
    word: &AtomicU32,
    value: u32,
    clock: u32,
    deadline: Option<u64>,
    owner: u32,
) -> Result<Woken, i32> {
    let me = crate::threads::own_block();
    let own = crate::threads::thread_number();
    {
        let _lock = PI_LOCK.lock();
        me.pi_addr
            .store(core::ptr::from_ref(word) as usize, Ordering::SeqCst);
        me.pi_level
            .store(u32::from(effective_level(me)), Ordering::SeqCst);
        me.pi_owner.store(owner, Ordering::SeqCst);
        if let Err(e) = propagate(own, u64::from(owner)) {
            me.pi_owner.store(0, Ordering::SeqCst);
            me.pi_addr.store(0, Ordering::SeqCst);
            return Err(e);
        }
    }
    let waited = posix_sync::futex_wait(word, value, clock, deadline);
    {
        let _lock = PI_LOCK.lock();
        // The holder took it off itself when it unlocked, or it is ours to do.
        let lent = me.pi_owner.swap(0, Ordering::SeqCst);
        me.pi_addr.store(0, Ordering::SeqCst);
        if lent != 0 {
            let _ = propagate(own, u64::from(lent));
        }
    }
    waited
}

/// The holder of a mutex of PTHREAD_PRIO_INHERIT unlocked `word`: the
/// levels its waiters lent it go off it at once, so that the highest of
/// them runs when it wakes; wakes up to `count`.
pub fn futex_wake_pi(word: *const AtomicU32, count: u32) -> u32 {
    let own = crate::threads::thread_number();
    // The lock keeps the caller at the ceiling of the process until its end,
    // so the wake comes first and the caller's level falls after it: the
    // waiter it wakes runs at once, before anything of a level between.
    let _lock = PI_LOCK.lock();
    let mut any = false;
    crate::relibc::each_live(|_, _, waiter| {
        if u64::from(waiter.pi_owner.load(Ordering::SeqCst)) == own
            && waiter.pi_addr.load(Ordering::SeqCst) == word as usize
        {
            waiter.pi_owner.store(0, Ordering::SeqCst);
            any = true;
        }
    });
    if any {
        let _ = propagate(0, own);
    }
    posix_sync::futex_wake(word, count)
}
