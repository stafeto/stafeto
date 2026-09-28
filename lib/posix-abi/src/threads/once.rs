// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Once initialization with IPC waiters and cancellation rollback. Application
//! threads publish completion or rollback themselves to synchronize their writes.

use super::{Registry, cancel, request, respond};
use crate::{constants::EINVAL, tls};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicU64, Ordering},
};
use rt::sys;

pub(super) const BEGIN: u64 = 14;
pub(super) const FINISH: u64 = 15;
pub(super) const RESET: u64 = 16;
const DONE: u64 = u64::MAX;
const INITIALIZE: u64 = 1;
const RETRY: u64 = 2;
#[cfg(feature = "transport-probe")]
static FINISH_READY: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "transport-probe")]
static FINISH_GATE: AtomicU64 = AtomicU64::new(0);
type Routine = unsafe extern "C" fn();

#[repr(C)]
pub struct Control {
    state: AtomicU64,
}
impl Control {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }
}
impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = {
    assert!(core::mem::size_of::<Control>() == 8);
    assert!(core::mem::align_of::<Control>() == 8);
};

pub(super) struct Waiting {
    control: u64,
    nonce: u64,
    token: sys::Token,
}

fn valid(address: u64) -> bool {
    address != 0 && address.is_multiple_of(core::mem::align_of::<Control>() as u64)
}

impl Registry {
    pub(super) fn once_begin(&mut self, caller: usize, words: [u64; 8], token: sys::Token) {
        if !valid(words[3]) {
            let answer = self.cache(caller, words[2], Err(EINVAL), BEGIN);
            respond(token, answer);
            return;
        }
        // SAFETY: the internal request borrows a live initialized once object.
        // A waiting caller never returns or abandons it before a terminal reply.
        let control = unsafe { &*(words[3] as *const Control) };
        // Drop an old interrupted wait even if completion was published before
        // FINISH reaches us. It must never overwrite this caller's later cache.
        self.entry_mut(caller).once_waiting = None;
        let state = control.state.load(Ordering::Acquire);
        if state == DONE || state == 0 {
            let result = if state == 0 {
                control.state.store(words[1], Ordering::Release);
                INITIALIZE
            } else {
                0
            };
            let answer = self.cache(caller, words[2], Ok(result), BEGIN);
            respond(token, answer);
        } else {
            // An externally interrupted wait retries this nonce and replaces
            // its rejected old token. Deferred cancellation is not taken here.
            self.entry_mut(caller).once_waiting = Some(Waiting {
                control: words[3],
                nonce: words[2],
                token,
            });
        }
    }
    pub(super) fn once_wake(&mut self, address: u64, result: u64) {
        for caller in 0..self.entries.len() {
            let Some(entry) = self.entries[caller].as_mut() else {
                continue;
            };
            if entry
                .once_waiting
                .as_ref()
                .is_some_and(|w| w.control == address)
            {
                let waiting = entry.once_waiting.take().expect("selected once waiter");
                let answer = self.cache(caller, waiting.nonce, Ok(result), BEGIN);
                respond(waiting.token, answer);
            }
        }
    }
    pub(super) fn once_perform(&mut self, words: [u64; 8]) -> Result<u64, i32> {
        if !valid(words[3]) {
            return Err(EINVAL);
        }
        match words[0] {
            FINISH => self.once_wake(words[3], 0),
            RESET => self.once_wake(words[3], RETRY),
            _ => return Err(EINVAL),
        }
        Ok(0)
    }
}

unsafe extern "C" fn rollback(argument: *mut c_void) {
    // SAFETY: the paired internal node retains its live once object until exit.
    let control = unsafe { &*(argument as *const Control) };
    control
        .state
        .compare_exchange(tls::thread_id(), 0, Ordering::Release, Ordering::Relaxed)
        .expect("once rollback ownership");
    request(RESET, [argument as u64, 0, 0, 0, 0]).expect("once rollback notification");
}

/// # Safety
/// control is a live, initialized static/extern once object shared only through
/// pthread_once. routine remains callable. Recursive calls on the same object
/// cannot complete; different nested objects are supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(control: *mut Control, routine: Option<Routine>) -> i32 {
    if !valid(control as u64) || routine.is_none() || super::current_launch().is_none() {
        return EINVAL;
    }
    let routine = routine.expect("checked once callback");
    let object = unsafe { &*control };
    loop {
        if object.state.load(Ordering::Acquire) == DONE {
            return 0;
        }
        match request(BEGIN, [control as u64, 0, 0, 0, 0]) {
            Ok(0) => {
                assert_eq!(
                    object.state.load(Ordering::Acquire),
                    DONE,
                    "once completion publication"
                );
                return 0;
            }
            Ok(INITIALIZE) => {
                // Acquire the owner's claim, including a previous rollback.
                assert_eq!(object.state.load(Ordering::Acquire), tls::thread_id());
                let mut cleanup = cancel::Cleanup::new();
                unsafe {
                    cancel::__stafeto_cleanup_push(&mut cleanup, Some(rollback), control.cast());
                    routine();
                    cancel::__stafeto_cleanup_pop(&mut cleanup, 0);
                }
                object.state.store(DONE, Ordering::Release);
                #[cfg(feature = "transport-probe")]
                finish_window();
                request(FINISH, [control as u64, 0, 0, 0, 0])
                    .expect("once completion notification");
                return 0;
            }
            Ok(RETRY) => continue,
            Ok(_) => panic!("invalid once owner reply"),
            Err(error) => return error,
        }
    }
}

#[cfg(feature = "transport-probe")]
pub fn probe_interrupt_replies() {
    super::INTERRUPT_REPLIES.fetch_or(
        (1 << BEGIN) | (1 << FINISH) | (1 << RESET),
        Ordering::AcqRel,
    );
}

/// Hold only the next completion after its Release publication, before FINISH.
#[cfg(feature = "transport-probe")]
pub fn probe_gate_finish(ready: u64, gate: u64) {
    FINISH_READY.store(ready, Ordering::Release);
    FINISH_GATE.store(gate, Ordering::Release);
}
#[cfg(feature = "transport-probe")]
fn finish_window() {
    let gate = FINISH_GATE.swap(0, Ordering::AcqRel);
    if gate != 0 {
        let ready = rt::handle::Handle::<rt::handle::Channel>::borrowed(rt::abi::Handle(
            FINISH_READY.load(Ordering::Acquire),
        ));
        let gate = rt::handle::Handle::<rt::handle::Channel>::borrowed(rt::abi::Handle(gate));
        sys::notify(&ready, 4).expect("once finish window");
        sys::receive(&gate).expect("once finish release");
    }
}
#[cfg(feature = "transport-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    request(17, [thread, 0, 0, 0, 0]).map(|value| value != 0)
}
