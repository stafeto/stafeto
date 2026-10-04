// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! One isolated native request loses its reply after the service's effect.
//! This module exists only in the dedicated IPC-loss guest kernel.

use crate::channel::{self, Via, Wait};
use crate::object::Object;
use crate::process::Process;
use crate::thread::{self, Thread};
use crate::{sched, session, syscall};
use abi::{Call, Error, Handle, ProcessState, Rights, ThreadState};
use core::cell::UnsafeCell;
use core::ptr::NonNull;
use kcore::args::Desc;

const ARM: u16 = 0xFFE0;
const SNAPSHOT: u16 = 0xFFE1;
const DISARM: u16 = 0xFFE2;

struct Arm {
    worker: NonNull<Thread>,
    via: Via,
    header: u64,
    slot: u32,
    generation: u64,
    body: u64,
    start: bool,
    sent: bool,
}

#[derive(Clone, Copy)]
struct Snapshot {
    // Values identify the test's process without borrowing its shell.
    owner: u64,
    ended: bool,
    alive: bool,
    result: u64,
    slot: u32,
    generation: u64,
}

struct State {
    arm: Option<Arm>,
    snapshot: Option<Snapshot>,
}

struct Probe(UnsafeCell<State>);
// SAFETY: the single-core kernel enters these hooks with IRQs masked.
// Hooks retain object references across scheduler mutations and never poll.
unsafe impl Sync for Probe {}
static PROBE: Probe = Probe(UnsafeCell::new(State {
    arm: None,
    snapshot: None,
}));

fn cause(t: NonNull<Thread>) -> u8 {
    // SAFETY: the caller holds t throughout this single-core entry.
    unsafe { t.as_ref().priority() }
}

fn owner(t: NonNull<Thread>) -> NonNull<Process> {
    // SAFETY: every hook's caller holds t, which holds its process.
    unsafe { t.as_ref().process() }
}

fn via(t: NonNull<Thread>, handle: u64) -> Result<Via, Error> {
    // SAFETY: the caller holds the thread and its process during lookup.
    unsafe { owner(t).as_ref() }.lookup(Handle(handle), Rights::SEND, |object| match *object {
        Object::Channel(c) => Some(Via::Channel(c)),
        Object::Session(s) => Some(Via::Session(s)),
        _ => None,
    })
}

fn release(arm: Arm, cause: u8) {
    // SAFETY: Arm owns precisely one reference of each object, removed
    // from the global state before release, outside the scheduler lock.
    unsafe {
        arm.via.let_go(cause);
        thread::release(arm.worker, cause);
    }
}

fn take() -> Option<Arm> {
    // SAFETY: single core with IRQs masked; no reference survives this access.
    unsafe { (*PROBE.0.get()).arm.take() }
}

/// The common scheduler exit path drops any arm before taking its lock.
pub fn ending(t: NonNull<Thread>, cause: u8) {
    // SAFETY: single core with IRQs masked; the arm owns its worker.
    let matches = unsafe { (*PROBE.0.get()).arm.as_ref().is_some_and(|a| a.worker == t) };
    if matches && let Some(arm) = take() {
        release(arm, cause);
    }
    // A value-only snapshot is invalidated by a further thread exit of
    // its process, including whole-process teardown.
    let process = owner(t).as_ptr() as u64;
    // SAFETY: the state has no borrow across scheduler mutation.
    unsafe {
        if (*PROBE.0.get())
            .snapshot
            .is_some_and(|s| s.owner == process)
        {
            (*PROBE.0.get()).snapshot = None;
        }
    }
}

fn arm(t: NonNull<Thread>) -> Result<(), Error> {
    if let Some(old) = take() {
        // SAFETY: the running caller is alive throughout the probe call.
        release(old, cause(t));
    }
    // SAFETY: only the running caller's registers are read.
    let args = unsafe { &t.as_ref().regs.x };
    if args[2] >= 32 || args[3] == 0 || args[5] > 1 {
        return Err(Error::InvalidArgs);
    }
    let endpoint = via(t, args[0])?;
    thread::retain(t);
    match endpoint {
        Via::Channel(c) => channel::retain(c, Rights::NONE),
        Via::Session(s) => session::retain(s, Rights::NONE),
    }
    let arm = Arm {
        worker: t,
        via: endpoint,
        header: args[1],
        slot: args[2] as u32,
        generation: args[3],
        body: args[4],
        start: args[5] == 0,
        sent: false,
    };
    // SAFETY: this entry owns the state, with retained references above.
    unsafe {
        (*PROBE.0.get()).snapshot = None;
        (*PROBE.0.get()).arm = Some(arm);
    }
    Ok(())
}

fn result(t: NonNull<Thread>, code: u64) {
    // SAFETY: t is the running test caller; x0 is its syscall result.
    unsafe { (*t.as_ptr()).regs.x[0] = code };
}

/// ARM: endpoint, Header64, slot, generation, expected jobID, start/job flag.
/// SNAPSHOT: x1 Ended, x2 Alive, x3 actual Reply result, x4 slot, x5 generation.
/// DISARM: release the current worker's arm once.
pub fn test_call(t: NonNull<Thread>, number: u16) -> bool {
    if number == ARM {
        result(t, arm(t).map_or_else(|e| e.code(), |()| 0));
        return true;
    }
    if number == DISARM {
        // SAFETY: the arm holds its worker; the caller holds t.
        let same = unsafe { (*PROBE.0.get()).arm.as_ref().is_none_or(|a| a.worker == t) };
        if same {
            if let Some(arm) = take() {
                release(arm, cause(t));
            }
            result(t, 0);
        } else {
            result(t, Error::AccessDenied.code());
        }
        return true;
    }
    if number == SNAPSHOT {
        // SAFETY: the snapshot contains values and the caller holds its process.
        let snapshot = unsafe { (*PROBE.0.get()).snapshot };
        if let Some(s) = snapshot.filter(|s| s.owner == owner(t).as_ptr() as u64) {
            // SAFETY: only the running caller's output registers are written.
            unsafe {
                let r = &mut (*t.as_ptr()).regs.x;
                r[0] = 0;
                r[1] = u64::from(s.ended);
                r[2] = u64::from(s.alive);
                r[3] = s.result;
                r[4] = s.slot as u64;
                r[5] = s.generation;
            }
        } else {
            result(t, Error::BadState.code());
        }
        return true;
    }
    if number == Call::Send.number() {
        // SAFETY: only the owned arm and running caller are read.
        let matches = unsafe { (*PROBE.0.get()).arm.as_ref().is_some_and(|a| a.worker == t) };
        if matches {
            // SAFETY: the caller's registers and arm live throughout this entry.
            let matches = unsafe {
                let a = (*PROBE.0.get()).arm.as_ref().unwrap();
                let r = &t.as_ref().regs.x;
                let body_matches = if a.start {
                    r[3] as u32 == a.slot
                        && (r[3] >> 32 | ((r[4] as u32 as u64) << 32)) == a.generation
                } else {
                    r[3] == a.body
                };
                r[2] == a.header
                    && via(t, r[0]) == Ok(a.via)
                    && body_matches
                    && Desc::from_send(r[1]).is_ok_and(|d| d.len >= if a.start { 20 } else { 16 })
            };
            if matches {
                // SAFETY: no borrow remains from the predicate above.
                unsafe { (*PROBE.0.get()).arm.as_mut().unwrap().sent = true };
            } else if let Some(arm) = take() {
                release(arm, cause(t));
            }
        }
        return false;
    }
    if number != Call::Reply.number() {
        return false;
    }
    // SAFETY: references below end before any mutation or recursive dispatch.
    let target = unsafe {
        let Some(a) = (*PROBE.0.get()).arm.as_ref() else {
            return false;
        };
        let r = &t.as_ref().regs.x;
        if !a.sent || r[2] as u32 != 0 || !Desc::from_reply(r[1]).is_ok_and(|d| d.len >= 8) {
            return false;
        }
        sched::locked(|k| {
            let client = k.tokens.check(r[0]).ok()?;
            (client == a.worker && client.as_ref().waits == Some(Wait::Reply(owner(t))))
                .then_some(client)
        })
    };
    let Some(worker) = target else {
        return false;
    };
    let Some(a) = take() else {
        return false;
    };
    if thread::end_waiting_for_probe(worker, owner(t)).is_err() {
        release(a, cause(t));
        return false;
    }
    let ended = thread::info(worker).state == ThreadState::Ended;
    // SAFETY: Arm still holds worker and its process while values are copied.
    let alive = unsafe { owner(worker).as_ref().state() == ProcessState::Alive };
    let process = owner(worker).as_ptr() as u64;
    // The empty Arm lets the ordinary Reply run exactly once. Its real
    // result remains in the server's registers for Token::reply to observe.
    syscall::dispatch(t, number);
    // SAFETY: the running server and owned Arm are still alive.
    unsafe {
        (*PROBE.0.get()).snapshot = Some(Snapshot {
            owner: process,
            ended,
            alive,
            result: t.as_ref().regs.x[0],
            slot: a.slot,
            generation: a.generation,
        });
    }
    release(a, cause(t));
    true
}
